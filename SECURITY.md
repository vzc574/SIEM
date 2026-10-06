# Security notes

This is a defensive SIEM MVP. Treat it as a development system until the
following controls are added and reviewed:

- Use a long, rotated API key and keep it outside source control.
- Keep the API behind TLS and a reverse proxy when exposed beyond localhost.
- Run malware analysis in a separate isolated sandbox; never execute samples
  in the SIEM container.
- Treat `sandbox-submit --spool-sample` as a controlled evidence-transfer
  operation and restrict access to the spool directory.
- Keep quarantine and report volumes access-controlled and backed up.
- Review AI-generated reports before taking action. AI output is advisory.
- Minimize sensitive evidence sent to external AI or threat-intelligence
  providers and confirm the organization's data-retention requirements.
- Add role-based users, rate limiting, centralized audit shipping, and routine
  dependency/image scanning before production use.
- Configure external threat-intelligence cache permissions so only the SIEM
  service account can read or write cached reputation data.
- Validate worker checkpoint and alert output recovery during supervisor or
  host restart drills.

The built-in API includes a basic per-process rate limit and security headers,
but production deployments should still place it behind a TLS reverse proxy
with distributed rate limiting and centralized monitoring.

The repository includes an Nginx secure deployment overlay. Certificates are
intentionally not included and must be provisioned through the organization's
certificate-management process.
