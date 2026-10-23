<#
.SYNOPSIS
  Ships Windows Security events to the SIEM's /ingest endpoint.

.DESCRIPTION
  Polls the Security log for the event IDs the SIEM understands, converts each
  to the JSON shape `ingestion.py --format windows-json` parses, and POSTs
  batches. The last delivered EventRecordID is saved after each successful
  batch, so restarts neither miss nor repeat events (the SIEM also
  de-duplicates retries).

  Requires: Windows PowerShell 5.1+, run as an account that can read the
  Security log (e.g. SYSTEM via a scheduled task), and an API key with the
  "ingest" role (SIEM_API_KEYS=win01:<key>=ingest on the SIEM).

.EXAMPLE
  # One-time setup (elevated PowerShell): store the key for SYSTEM only.
  New-Item -ItemType Directory -Force C:\ProgramData\SIEM | Out-Null
  Set-Content -Path C:\ProgramData\SIEM\ingest.key -Value '<ingest key>' -NoNewline
  icacls C:\ProgramData\SIEM /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"

  # Run in the foreground to test:
  .\siem-collector.ps1 -SiemUrl https://siem.example.com

  # Install as a startup task running as SYSTEM:
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\SIEM\siem-collector.ps1 -SiemUrl https://siem.example.com'
  Register-ScheduledTask -TaskName 'SIEM Collector' -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) -User 'SYSTEM' -RunLevel Highest
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $SiemUrl,
    [string] $KeyFile = 'C:\ProgramData\SIEM\ingest.key',
    [string] $StateFile = 'C:\ProgramData\SIEM\collector-state.json',
    [int] $IntervalSeconds = 15,
    [int] $BatchSize = 500,
    # 4624/4625 logon, 4688 process, 4720 user created, 4732 group add,
    # 4740 lockout, 1102 log cleared, 4104 PowerShell script block (other log, ignored here)
    [int[]] $EventIds = @(4624, 4625, 4688, 4720, 4732, 4740, 1102),
    [switch] $Once
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not $SiemUrl.StartsWith('https://') -and -not $SiemUrl.StartsWith('http://localhost') -and -not $SiemUrl.StartsWith('http://127.0.0.1')) {
    throw 'SiemUrl must use https:// (http is only allowed for localhost).'
}
$endpoint = $SiemUrl.TrimEnd('/') + '/ingest'
$apiKey = (Get-Content -Path $KeyFile -Raw).Trim()
$source = "windows-$($env:COMPUTERNAME.ToLower())"

function Get-LastRecordId {
    if (Test-Path $StateFile) {
        try { return [long]((Get-Content $StateFile -Raw | ConvertFrom-Json).last_record_id) } catch { }
    }
    # First run: start from the newest event instead of shipping the whole log.
    $newest = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($newest) { return [long]$newest.RecordId }
    return [long]0
}

function Save-LastRecordId([long] $RecordId) {
    $temporary = "$StateFile.tmp"
    @{ last_record_id = $RecordId } | ConvertTo-Json -Compress | Set-Content -Path $temporary -NoNewline
    Move-Item -Path $temporary -Destination $StateFile -Force
}

function ConvertTo-SiemLine($Event) {
    $xml = [xml]$Event.ToXml()
    $data = @()
    foreach ($item in @($xml.Event.EventData.Data)) {
        if ($item -and $item.Name) { $data += @{ Name = [string]$item.Name; '#text' = [string]$item.'#text' } }
    }
    $record = @{
        Event   = @{
            System    = @{
                EventID     = $Event.Id
                # Six fractional digits: what Python's ISO parser accepts on every version.
                TimeCreated = $Event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'")
                Computer    = $Event.MachineName
                Provider    = @{ Name = $Event.ProviderName }
                EventRecordID = $Event.RecordId
            }
            EventData = @{ Data = $data }
        }
        Message = ($Event.Message -split "`r?`n")[0]
    }
    return ($record | ConvertTo-Json -Compress -Depth 6)
}

function Send-Batch([string[]] $Lines) {
    $body = @{ format = 'windows-json'; source = $source; lines = $Lines } | ConvertTo-Json -Compress -Depth 3
    $bytes = [Text.Encoding]::UTF8.GetBytes($body)
    $response = Invoke-RestMethod -Uri $endpoint -Method Post -Body $bytes -ContentType 'application/json' `
        -Headers @{ 'X-API-Key' = $apiKey } -TimeoutSec 30
    if ($response.rejected -gt 0) {
        Write-Warning "SIEM rejected $($response.rejected) event(s): $($response.errors -join '; ')"
    }
    return $response.accepted
}

$lastRecordId = Get-LastRecordId
Write-Host "SIEM collector: $source -> $endpoint (after record $lastRecordId)"
$idFilter = ($EventIds | ForEach-Object { "EventID=$_" }) -join ' or '

while ($true) {
    try {
        $xpath = "*[System[($idFilter) and EventRecordID > $lastRecordId]]"
        $events = @(Get-WinEvent -LogName Security -FilterXPath $xpath -ErrorAction SilentlyContinue |
            Sort-Object RecordId | Select-Object -First ($BatchSize * 10))
        for ($start = 0; $start -lt $events.Count; $start += $BatchSize) {
            $batch = $events[$start..([Math]::Min($start + $BatchSize, $events.Count) - 1)]
            $accepted = Send-Batch -Lines @($batch | ForEach-Object { ConvertTo-SiemLine $_ })
            $lastRecordId = [long]$batch[-1].RecordId
            Save-LastRecordId $lastRecordId
            Write-Host "$(Get-Date -Format s) shipped $accepted event(s), up to record $lastRecordId"
        }
    } catch {
        # Delivery failed: the checkpoint was not advanced, so this batch is retried.
        Write-Warning "$(Get-Date -Format s) collection failed, will retry: $($_.Exception.Message)"
    }
    if ($Once) { break }
    Start-Sleep -Seconds $IntervalSeconds
}
