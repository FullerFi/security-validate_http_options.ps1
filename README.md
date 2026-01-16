# Validate-HttpOptions.ps1

Validate whether the HTTP **OPTIONS** method is enabled on a list of servers and generate audit‑friendly results for remediation tracking (e.g., PCI DSS 11.3.1 follow‑up).

## Why
Some scanners flag `HTTP OPTIONS Method Enabled` as a finding. This script sends an `OPTIONS` request to each target and records whether the method is explicitly allowed (via the `Allow:` header), not listed, or blocked (e.g., `405 Method Not Allowed`). The output is a timestamped log you can attach to tickets or remediation projects.

## Features
- 🧪 Sends HTTP **OPTIONS** requests to `/` for each target
- 🔒 HTTPS by default; optional fallback to HTTP:80
- 📜 Captures and parses the `Allow:` header (if present)
- 🧭 Handles non-2xx responses (e.g., `405` with `Allow:`)
- 🧰 Works on Windows PowerShell 5.1 and PowerShell 7+
- 🧾 Writes a CSV-like log: `Server:Port,Status,Details`
- 🛡️ Optional TLS trust bypass for internal/self-signed testing

## Input Format
One target per line in a text file. Supported forms:
- `server:port`
- `https://server:port`
- `http://server:port`
- `[IPv6]:port`
- `server` (defaults to `https:443`; optional fallback to `http:80` when `-TryHttpFallback` is set)

> Tip: Keep comments using `#` and blank lines—they are ignored.

## Output
Creates a timestamped log in the current directory, e.g.:
