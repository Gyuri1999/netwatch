# NetWatch για Windows 10/11
#   .\run.bat                              live καταγραφή (θέλει Npcap — https://npcap.com)
#   .\run.bat --demo                       προσομοίωση κίνησης & επιθέσεων
#   .\run.bat --pcap samples\lan-attack.pcap   αναπαραγωγή αρχείου καταγραφής
#   .\run.bat -Admin                       ως διαχειριστής (για μπλοκάρισμα IP στο Τείχος προστασίας,
#                                          ή αν το Npcap εγκαταστάθηκε «μόνο για διαχειριστές»)
#   .\run.bat -Shortcut                    φτιάχνει συντόμευση «NetWatch» στην επιφάνεια εργασίας
#   .\run.bat --list-ifaces                ποιες διεπαφές βλέπει η καταγραφή (για -i "Wi-Fi")
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$admin = $args -contains '-Admin'
$shortcut = $args -contains '-Shortcut'
$rest = @($args | Where-Object { $_ -ne '-Admin' -and $_ -ne '-Shortcut' })

if ($shortcut) {
    $lnk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'NetWatch.lnk'
    $sh = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
    $sh.TargetPath = Join-Path $PSScriptRoot 'run.bat'
    $sh.WorkingDirectory = $PSScriptRoot
    $ico = Join-Path $PSScriptRoot 'macapp\NetWatch.ico'
    if (Test-Path $ico) { $sh.IconLocation = $ico }
    $sh.Save()
    Write-Host "Έτοιμο: $lnk"
    exit 0
}

if ($admin) {
    $me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $q = @($rest | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' })
        Start-Process -Verb RunAs -FilePath 'powershell.exe' -ArgumentList (
            @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"") + $q)
        exit 0
    }
}

# --- Python 3.9+ ---
function Find-Python {
    foreach ($c in @(@('py', '-3'), @('python'), @('python3'))) {
        $exe = Get-Command $c[0] -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        # το «python» του Microsoft Store χωρίς εγκατεστημένη Python ανοίγει το Store — το προσπερνάμε
        if ($exe.Source -like '*WindowsApps*') { continue }
        $pre = @($c | Select-Object -Skip 1)
        $v = & $c[0] @pre -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>$null
        if ($LASTEXITCODE -eq 0 -and [version]$v -ge [version]'3.9') { return , $c }
    }
    return $null
}

$venvPy = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPy)) {
    $py = Find-Python
    if (-not $py) {
        Write-Host '✖ Δεν βρέθηκε Python 3.9 ή νεότερη.' -ForegroundColor Red
        Write-Host '  Εγκατάστησέ την με:  winget install Python.Python.3.12'
        Write-Host '  ή από https://www.python.org/downloads/windows/ (τσέκαρε «Add python.exe to PATH»)'
        exit 1
    }
    Write-Host 'Εγκατάσταση εξαρτήσεων στο .venv …'
    $pre = @($py | Select-Object -Skip 1)
    & $py[0] @pre -m venv .venv
    if ($LASTEXITCODE -ne 0) { exit 1 }
    & $venvPy -m pip install -q --disable-pip-version-check -r requirements.txt
    if ($LASTEXITCODE -ne 0) { Remove-Item -Recurse -Force .venv; exit 1 }
}

$offline = ($rest -contains '--demo') -or ($rest -contains '--pcap') -or ($rest -contains '--list-ifaces') -or `
           ($rest -contains '-h') -or ($rest -contains '--help')
$npcap = (Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll")
if (-not $offline -and -not $npcap) {
    Write-Host '✖ Για live καταγραφή χρειάζεται το Npcap: https://npcap.com/#download' -ForegroundColor Yellow
    Write-Host '  (στην εγκατάσταση άφησε τσεκαρισμένο το «Install Npcap in WinPcap API-compatible Mode»)'
    $a = Read-Host 'Να ξεκινήσει σε Demo στο μεταξύ; [Ν/ο]'
    if ($a -match '^(ο|o|n|no|όχι)$') { exit 1 }
    $rest = @('--demo') + $rest
}

$env:PYTHONUTF8 = '1'
& $venvPy -X utf8 netwatch.py @rest
exit $LASTEXITCODE
