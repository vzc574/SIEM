# Deploying the SIEM on AWS EC2

`setup-ec2.sh` turns a fresh Ubuntu 24.04 instance into a running SIEM:
Docker, the API/dashboard, the detection worker, an agent tailing the
instance's own `/var/log/auth.log`, nginx with a Let's Encrypt certificate,
a host firewall, daily verified database backups, and automatic certificate
renewal.

> The script was checked with `bash -n` and ShellCheck but has not been run
> against a real instance yet. Run it on a test instance first.

## 1. AWS console

1. **Launch an instance**: Ubuntu Server 24.04 LTS, `t3.small` (2 GB RAM) or
   larger, 20 GB gp3 disk. Create or choose an SSH key pair.
2. **Security group**, inbound rules:
   | Port | Source | Why |
   |---|---|---|
   | 22 | *My IP* only | SSH administration |
   | 80 | 0.0.0.0/0 | Let's Encrypt validation and redirect to HTTPS |
   | 443 | 0.0.0.0/0 (or your office/VPN range) | Dashboard and `/ingest` for collectors |

   Never open 8080; the API is only reachable through nginx.
3. **Elastic IP**: allocate one and associate it with the instance, so the
   address survives restarts.
4. **DNS**: create an `A` record (e.g. `siem.example.com`) pointing at the
   Elastic IP. Wait until `dig +short siem.example.com` returns it.

## 2. On the instance

```bash
ssh -i your-key.pem ubuntu@siem.example.com
curl -fsSLO https://raw.githubusercontent.com/vzc574/SIEM/master/deploy/aws/setup-ec2.sh
less setup-ec2.sh                      # read it before running it as root
chmod +x setup-ec2.sh
sudo ./setup-ec2.sh --domain siem.example.com --email you@example.com
```

At the end it asks for a password for the first dashboard admin. Then open
`https://siem.example.com/` and sign in.

Re-running the script later updates the code (`git pull`) and restarts the
stack; `.env`, certificates and data are kept.

## 3. Afterwards

- **Notifications**: edit `/opt/siem/.env` (Slack, Telegram or SMTP settings),
  then `cd /opt/siem && sudo docker compose -f docker-compose.yml -f docker-compose.secure.yml --profile agent up -d`.
- **More users**: `sudo docker compose exec siem python database.py user-add alice --role analyst`
- **Other servers**: on each Linux host, run the agent with the
  `remote-collector` key from `.env`:
  `SIEM_INGEST_KEY=<key> python3 ingestion.py agent /var/log/auth.log --format syslog --ship-to https://siem.example.com`.
  For Windows hosts, see `deploy/windows/siem-collector.ps1`.
- **Logs**: `sudo docker compose logs -f worker` (and `siem`, `agent`, `proxy`).
- **Backups** land in `/var/backups/siem` daily (14 days kept). Copy them
  off the instance too, e.g. to S3: `aws s3 sync /var/backups/siem s3://your-bucket/siem/`.
- **Restore**: stop the stack, then
  `sudo docker compose cp /var/backups/siem/siem-YYYY-MM-DD.db siem:/app/data/siem.db`, and start it again.

Expect real SSH brute-force alerts within hours of the instance going online.
That is the internet's normal background noise, and a good first demo.

## Cost and teardown

A `t3.small` with 20 GB costs roughly US$17-20 per month on demand (less with
the free tier or a savings plan). An Elastic IP is free only while it is
attached to a running instance. To stop paying, terminate the instance,
**release the Elastic IP**, and delete the DNS record.
