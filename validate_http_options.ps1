<#
.SYNOPSIS
  Validates whether the HTTP OPTIONS method is enabled on a list of servers.

.DESCRIPTION
  Reads a server list and sends HTTP OPTIONS requests to each target.
  Accepts lines in the form:
    - server:port
    - https://server:port
    - http://server:port
    - [IPv6]:port
    - server            (if no port given, defaults to 443; optional fallback to 80)

  Logs results as CSV-like text with columns:
    Server:Port,Status,Details

.PARAMETER ServerList
  Path to the input text file (one host per line).

.PARAMETER TimeoutSec
  Timeout for each request (seconds). Default: 10

.PARAMETER OutputPath
  Optional explicit output file. Defaults to "http_options_validation_<timestamp>.log" in current dir.

.PARAMETER TryHttpFallback
  If set: when scheme is omitted or HTTPS fails, try HTTP:80 as a fallback.

.PARAMETER SkipCertValidation
  If set: ignore TLS certificate validation errors (use only on internal testing per policy).

.EXAMPLE
  .\Validate-HttpOptions.ps1 -ServerList .\servers.txt

.EXAMPLE
  .\Validate-HttpOptions.ps1 -ServerList .\servers.txt -TryHttpFallback -SkipCertValidation -TimeoutSec 5
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$ServerList,

    [int]$TimeoutSec = 10,

    [string]$OutputPath = $(Join-Path -Path (Get-Location) -ChildPath ("http_options_validation_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))),

    [switch]$TryHttpFallback,

    [switch]$SkipCertValidation
)

# --- Console coloring helper ---
function Write-Status {
    param(
        [Parameter(Mandatory=$true)][ValidateSet('SUCCESS','FAILED','WARNING','INFO')]$Level,
        [Parameter(Mandatory=$true)][string]$Message
    )
    switch ($Level) {
        'SUCCESS' { Write-Host "[✓] $Message" -ForegroundColor Green }
        'FAILED'  { Write-Host "[✗] $Message" -ForegroundColor Red }
        'WARNING' { Write-Host "[!] $Message" -ForegroundColor Yellow }
        'INFO'    { Write-Host "[i] $Message" -ForegroundColor Cyan }
    }
}

# Ensure TLS 1.2 is enabled (helps with older .NET defaults on WinPS 5.1)
try {
    [void][Net.ServicePointManager]::SecurityProtocol
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# Optional: bypass TLS validation for internal/self-signed scenarios (if requested)
if ($SkipCertValidation) {
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        Write-Status INFO "TLS certificate validation is disabled for this session"
    } catch {
        Write-Status WARNING "Could not disable TLS validation (insufficient permissions or environment restriction)"
    }
}

# Initialize output file
"Server:Port,Status,Details" | Out-File -FilePath $OutputPath -Encoding utf8 -Force

# Regex to parse [scheme://]host[:port] (IPv6 host supported with [brackets])
$targetRegex = '^(?<scheme>https?://)?(?<host>\[[^\]]+\]|[^:/\[]+)(?::(?<port>\d+))?$'

# Core test function
function Test-HttpOptions {
    param(
        [Parameter(Mandatory=$true)][string]$Target,
        [int]$TimeoutSecLocal = 10,
        [switch]$TryHttpFallbackLocal
    )

    # Trim whitespace
    $Target = $Target.Trim()

    # Skip blank lines / comments
    if ([string]::IsNullOrWhiteSpace($Target) -or $Target -match '^\s*#') {
        return $null
    }

    if ($Target -notmatch $targetRegex) {
        $msg = "Invalid format: '$Target' (expected host[:port] or [scheme://]host[:port]; IPv6 in [brackets])"
        return [pscustomobject]@{
            Display     = $Target
            Status      = 'WARNING'
            Details     = 'Invalid format'
            Info        = $msg
        }
    }

    $Scheme = if ($Matches['scheme']) { $Matches['scheme'] } else { '' }
    $Hostname   = $Matches['host']
    $Port   = $Matches['port']

    $urlsToTry = New-Object System.Collections.Generic.List[string]

    if ($Scheme) {
        # Scheme explicitly provided
        if (-not $Port) {
            # Default port by scheme
            $Port = if ($Scheme -eq 'https://') { '443' } else { '80' }
        }
        $urlsToTry.Add(("{0}{1}:{2}/" -f $Scheme, $Hostname, $Port))
    } else {
        # No scheme provided
        if ($Port) {
            # Assume HTTPS when a port is provided without scheme
            $urlsToTry.Add(("https://{0}:{1}/" -f $Hostname, $Port))
        } else {
            # No port at all: default HTTPS:443
            $urlsToTry.Add(("https://{0}:443/" -f $Hostname))
            if ($TryHttpFallbackLocal) {
                # Also consider HTTP:80 if fallback requested
                $urlsToTry.Add(("http://{0}:80/" -f $Hostname))
            }
        }
    }

    # Local helper to perform OPTIONS using Invoke-WebRequest
    function Invoke-Options {
        param([string]$Url, [int]$Timeout)
        # Result object: Headers, StatusCode, Error, NetworkError, DisplayUrl
        $result = [ordered]@{
            Url          = $Url
            StatusCode   = $null
            Headers      = $null
            Error        = $null
            NetworkError = $null
        }
        try {
            # PowerShell 7+: -SkipHttpErrorCheck keeps non-2xx as non-terminating, but we support 5.1 via try/catch
            $resp = $null
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $resp = Invoke-WebRequest -Method Options -Uri $Url -TimeoutSec $Timeout -SkipHttpErrorCheck -ErrorAction Stop
                # In PS7, StatusCode is available; Headers as well
                $result.StatusCode = [int]$resp.StatusCode
                $result.Headers    = $resp.Headers
            } else {
                # Windows PowerShell 5.1: non-2xx throws WebException, catch to read Response
                $resp = Invoke-WebRequest -Method Options -Uri $Url -TimeoutSec $Timeout -ErrorAction Stop
                $result.StatusCode = 200
                $result.Headers    = $resp.Headers
            }
        } catch [System.Net.WebException] {
            $we = $_.Exception
            if ($we.Response) {
                # We still can parse status and headers (e.g., 301, 401, 405, etc.)
                try {
                    $httpResp = [System.Net.HttpWebResponse]$we.Response
                    $result.StatusCode = [int]$httpResp.StatusCode
                    $result.Headers    = $httpResp.Headers
                } catch {
                    $result.Error = $we.Message
                }
            } else {
                # Pure network error (DNS, connect, timeout, TLS)
                $result.NetworkError = $we.Status.ToString()  # NameResolutionFailure, ConnectFailure, Timeout, TrustFailure, etc.
                $result.Error        = $we.Message
            }
        } catch {
            $result.Error = $_.Exception.Message
        }
        return [pscustomobject]$result
    }

    foreach ($url in $urlsToTry) {
        Write-Status INFO "Testing OPTIONS on $url"

        $res = Invoke-Options -Url $url -Timeout $TimeoutSecLocal

        $allowHeader = $null
        $statusCode  = $res.StatusCode

        if ($res.Headers) {
            # Headers is a WebHeaderCollection or IDictionary; get case-insensitively
            if ($res.Headers['Allow']) {
                # Join multiple header instances if present
                $allowHeader = ($res.Headers.GetValues('Allow') -join ',')
            } else {
                # Some servers may include lowercase/odd casing (rare)
                foreach ($key in $res.Headers.Keys) {
                    if ($key -and ($key.ToString()).ToLower() -eq 'allow') {
                        $allowHeader = ($res.Headers[$key] -join ',')
                        break
                    }
                }
            }
        }

        if ($res.NetworkError) {
            # Network failure on this URL; try next URL if any
            Write-Status FAILED ("{0} - Connection failed ({1})" -f ($url -replace 'https?://','' -replace '/$',''), $res.NetworkError)
            continue
        }

        if ($null -ne $statusCode) {
            # Determine status based on Allow and code
            $allowText = if ($allowHeader) { $allowHeader } else { 'Not present' }

            if ($allowHeader -and ($allowHeader -match '(?i)\bOPTIONS\b')) {
                # OPTIONS explicitly allowed
                return [pscustomobject]@{
                    Display = ($url -replace 'https?://','' -replace '/$','')
                    Status  = 'SUCCESS'
                    Details = "OPTIONS enabled - $allowText"
                    Info    = "HTTP $statusCode"
                }
            }

            if ($statusCode -eq 405 -and $allowHeader) {
                # Method Not Allowed, but Allow header present and excludes OPTIONS
                return [pscustomobject]@{
                    Display = ($url -replace 'https?://','' -replace '/$','')
                    Status  = 'WARNING'
                    Details = "405; OPTIONS not in Allow - $allowText"
                    Info    = "HTTP $statusCode"
                }
            }

            if ($statusCode -in 200,204) {
                # Responds OK/No Content but no Allow header or no OPTIONS listed
                return [pscustomobject]@{
                    Display = ($url -replace 'https?://','' -replace '/$','')
                    Status  = 'WARNING'
                    Details = "Server responds; Allow missing or excludes OPTIONS"
                    Info    = "HTTP $statusCode; Allow: $allowText"
                }
            }

            # Anything else: treat as failed/not supported/advertised
            return [pscustomobject]@{
                Display = ($url -replace 'https?://','' -replace '/$','')
                Status  = 'FAILED'
                Details = "HTTP $statusCode - OPTIONS not supported/advertised; Allow: $allowText"
                Info    = "HTTP $statusCode"
            }
        }

        # No status code and no headers => hard failure on this URL; try next
        Write-Status FAILED ("{0} - No response" -f ($url -replace 'https?://','' -replace '/$',''))
    }

    # If we got here, all attempts failed
    return [pscustomobject]@{
        Display = $Target
        Status  = 'FAILED'
        Details = "Connection failed for all attempts"
        Info    = ''
    }
}

# --- Main ---
Write-Status INFO  "HTTP OPTIONS Method Validation (PowerShell)"
Write-Status INFO  "Server list: $ServerList"
Write-Status INFO  "Results file: $OutputPath"
Write-Host ""

# Counters
[int]$total    = 0
[int]$success  = 0
[int]$failed   = 0
[int]$warnings = 0

# Read input and process
$lines = Get-Content -Path $ServerList -ErrorAction Stop

foreach ($line in $lines) {
    $result = Test-HttpOptions -Target $line -TimeoutSecLocal $TimeoutSec -TryHttpFallbackLocal:$TryHttpFallback

    if ($null -eq $result) { continue } # blank/comment

    switch ($result.Status) {
        'SUCCESS' { $success++ ; Write-Status SUCCESS ("{0} - {1}" -f $result.Display, $result.Info) ; Write-Status INFO ("  Allow/Details: {0}" -f $result.Details) }
        'WARNING' { $warnings++; Write-Status WARNING ("{0} - {1}" -f $result.Display, $result.Info) ; Write-Status INFO ("  Details: {0}" -f $result.Details) }
        'FAILED'  { $failed++  ; Write-Status FAILED  ("{0} - {1}" -f $result.Display, $result.Info) ; if ($result.Details) { Write-Status INFO ("  Details: {0}" -f $result.Details) } }
    }

    # Append to log
    ("{0},{1},{2}" -f $result.Display, $result.Status, $result.Details) | Add-Content -Path $OutputPath -Encoding utf8
    $total++
    Write-Host ""
}

# Summary
Write-Host "============================================"
Write-Status INFO    "Validation Complete!"
Write-Status INFO    ("Total tested: {0}" -f $total)
Write-Status SUCCESS ("OPTIONS enabled: {0}" -f $success)
Write-Status FAILED  ("Failed/Not supported: {0}" -f $failed)
Write-Status WARNING ("Warnings: {0}" -f $warnings)
Write-Status INFO    "Detailed results saved to: $OutputPath"
Write-Host ""
Write-Status INFO "Results summary (tail):"
Write-Host "----------------------------------------"
Get-Content -Path $OutputPath -Tail 10
