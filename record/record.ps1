# record/record.ps1 — Demo recording script
# Runs full redcheck flow and tees output to record/redcheck.log
# Optionally uses asciinema if installed.

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir   = Split-Path -Parent $ScriptDir
$LogFile   = "$ScriptDir\redcheck.log"

Push-Location $RootDir

$timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
"[RedCheck RECORD] $timestamp" | Tee-Object -FilePath $LogFile

# Check if asciinema is available
$asciinema = Get-Command asciinema -ErrorAction SilentlyContinue

if ($asciinema) {
    $castFile = "$ScriptDir\redcheck.cast"
    Write-Host "[record] asciinema found — recording to $castFile"
    & asciinema rec $castFile --command "powershell -NoProfile -File `"$ScriptDir\record_inner.ps1`""
} else {
    Write-Host "[record] asciinema not found — logging to $LogFile"
    & powershell -NoProfile -Command {
        cd $using:RootDir
        Write-Host "=== redcheck-vuln ===" | Tee-Object -Append -FilePath $using:LogFile
        python -m redcheck.runner --mode vuln 2>&1 | Tee-Object -Append -FilePath $using:LogFile
        Write-Host "=== redcheck-hardened ===" | Tee-Object -Append -FilePath $using:LogFile
        python -m redcheck.runner --mode hardened 2>&1 | Tee-Object -Append -FilePath $using:LogFile
        Write-Host "=== compare ===" | Tee-Object -Append -FilePath $using:LogFile
        python -m redcheck.report --vuln out/redcheck_vuln.json --hardened out/redcheck_hardened.json --out out/compare.html 2>&1 | Tee-Object -Append -FilePath $using:LogFile
    }
}

Pop-Location
Write-Host "[record] Done. Log: $LogFile"
