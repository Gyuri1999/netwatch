# Φτιάχνει την εφαρμογή NetWatch για Windows (x64), σε Windows 10/11 με Python 3.12:
#   powershell -ExecutionPolicy Bypass -File winapp\build.ps1
# Αποτέλεσμα:
#   dist\NetWatch\               NetWatch.exe + python\ (ενσωματωμένη) + app\ (ο κώδικας)
#   dist\NetWatch-windows-x64.zip
# Δεν χρειάζεται εγκατεστημένη Python στον υπολογιστή που θα το τρέξει — μόνο το Npcap για Live.
param([string]$PyVersion = '3.12.8')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-Location (Split-Path -Parent $PSScriptRoot)
$root = (Get-Location).Path
$out = Join-Path $root 'dist\NetWatch'
$build = Join-Path $root 'build\winapp'
Remove-Item -Recurse -Force $out, $build -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $out, $build | Out-Null

$hostVer = (& python -c 'import sys; print("%d.%d" % sys.version_info[:2])')
$want = ($PyVersion -split '\.')[0..1] -join '.'
if ($hostVer -ne $want) { throw "Χρειάζεται Python $want για το build (βρέθηκε $hostVer): τα wheels πρέπει να ταιριάζουν με την ενσωματωμένη." }

Write-Host '▸ ενσωματωμένη Python' $PyVersion
$zip = Join-Path $build 'python-embed.zip'
Invoke-WebRequest "https://www.python.org/ftp/python/$PyVersion/python-$PyVersion-embed-amd64.zip" -OutFile $zip
$py = Join-Path $out 'python'
Expand-Archive $zip -DestinationPath $py
# Η embeddable δεν φορτώνει site-packages εξ ορισμού: το ενεργοποιούμε στο ._pth
$pth = Get-ChildItem $py -Filter 'python3*._pth' | Select-Object -First 1
$lines = (Get-Content $pth.FullName) -replace '^#\s*import site', 'import site'
Set-Content $pth.FullName (@($lines) + 'Lib\site-packages') -Encoding ascii

Write-Host '▸ εξαρτήσεις (scapy, pyyaml, paho-mqtt)'
& python -m pip install --disable-pip-version-check -q --only-binary=:all: --platform win_amd64 `
    --python-version $want --implementation cp --target (Join-Path $py 'Lib\site-packages') -r requirements.txt
if ($LASTEXITCODE) { throw 'pip install απέτυχε' }

Write-Host '▸ κώδικας NetWatch'
$app = Join-Path $out 'app'
New-Item -ItemType Directory -Force $app | Out-Null
$files = @(git ls-files) | Where-Object {
    ($_ -notmatch '/' -and $_ -match '\.(py|js|html|webmanifest|yaml|txt)$' -and $_ -notmatch '^(requirements-dev|docker-compose)') -or
    ($_ -match '^(i18n|vendor|academy|rules|ctf|samples)/')
}
foreach ($f in $files + @('VERSION', 'update_signers')) {
    if (-not (Test-Path $f)) { continue }
    $dst = Join-Path $app $f
    New-Item -ItemType Directory -Force (Split-Path -Parent $dst) | Out-Null
    Copy-Item $f $dst
}
Remove-Item (Join-Path $app 'rules\local.yaml') -ErrorAction SilentlyContinue
$sha = (git rev-parse --short HEAD)
Set-Content (Join-Path $app '.build_id') "$sha $(Get-Date -Format o)" -Encoding ascii

Write-Host '▸ NetWatch.exe (PyInstaller)'
& python -m pip install --disable-pip-version-check -q pyinstaller pystray pillow
& python -c @"
from PIL import Image
im = Image.open(r'academy/icon-512.png').convert('RGBA')
im.save(r'$build\NetWatch.ico', sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
"@
& python -m PyInstaller --noconfirm --clean --windowed --name NetWatch --icon "$build\NetWatch.ico" `
    --distpath $build\exe --workpath $build\work --specpath $build `
    --hidden-import pystray._win32 winapp\launcher.py
if ($LASTEXITCODE) { throw 'PyInstaller απέτυχε' }
Copy-Item -Recurse "$build\exe\NetWatch\*" $out

@"
NetWatch για Windows 10/11
==========================

1. Διπλό κλικ στο NetWatch.exe. Εμφανίζεται μια ασπίδα στο system tray (κάτω δεξιά, ίσως στο ^)
   και ανοίγει ο πίνακας σε δικό του παράθυρο.
2. Για Live (πραγματική κίνηση) εγκατάστησε το δωρεάν Npcap: https://npcap.com/#download
   (άφησε τσεκαρισμένο το «Install Npcap in WinPcap API-compatible Mode»). Χωρίς Npcap δουλεύουν
   το Demo και η αναπαραγωγή αρχείων .pcap.
3. Από το μενού της ασπίδας αλλάζεις Live / Demo / pcap. Το «Live ως διαχειριστής» χρειάζεται για
   το μπλοκάρισμα IP στο Τείχος προστασίας των Windows.

Το ιστορικό και οι ρυθμίσεις μένουν στο %LOCALAPPDATA%\NetWatch.

Την πρώτη φορά τα Windows μπορεί να πουν «Τα Windows προστάτευσαν τον υπολογιστή σας»: η εφαρμογή
δεν είναι υπογεγραμμένη με πιστοποιητικό. Πάτα «Περισσότερες πληροφορίες» → «Εκτέλεση οπωσδήποτε».
"@ | Set-Content (Join-Path $out 'ΔΙΑΒΑΣΕ ΜΕ.txt') -Encoding utf8

Write-Host '▸ zip'
$z = Join-Path $root 'dist\NetWatch-windows-x64.zip'
Remove-Item $z -ErrorAction SilentlyContinue
Compress-Archive -Path $out -DestinationPath $z
Write-Host "✔ $out"
Write-Host "✔ $z ($([math]::Round((Get-Item $z).Length / 1MB, 1)) MB)"
