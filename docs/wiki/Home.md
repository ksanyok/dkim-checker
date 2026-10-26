# DKIM Checker

`dkim-checker` looks up `<selector>._domainkey.<domain>`, parses the key record and actually decodes the public key, so it can tell you the real key length (1024 vs. 2048 bits), spot revoked keys, testing mode and broken base64. Don't know your selector? Run it with just the domain and it probes the selectors used by Google Workspace, Microsoft 365, Mailchimp, SendGrid, Zoho, Proton and others.

- **[Getting started](Getting-Started)** — install, first run, reading the output
- **[FAQ](FAQ)** — common questions
- **[Troubleshooting](Troubleshooting)** — errors and how to fix them

Prefer a browser? The same check runs online at **[PromoPilot](https://promopilot.link/en/tools/dkim-checker.php?utm_source=github&utm_medium=repo&utm_campaign=tools&utm_content=dkim-checker)** — free, no sign-up.
