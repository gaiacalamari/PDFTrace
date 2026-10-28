<#
PDFTrace - installation of the optional Toolbox tools on Windows (Scoop).

Scoop installs every program in the user profile and adds it to PATH through
its shims folder: no administrator rights and no manual PATH editing.
Usage (PowerShell):
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\scripts\install-tools.ps1                 # all tools, including Tesseract OCR
    .\scripts\install-tools.ps1 -OcrOnly        # only Tesseract and its language data
    .\scripts\install-tools.ps1 -Languages ita,eng,deu
#>
param(
    [switch]$SkipPoppler,
    [switch]$OcrOnly,
    [string[]]$Languages = @("ita", "eng")
)
$ErrorActionPreference = "Stop"

if (-not (Get-Command scoop -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Scoop (https://scoop.sh)..."
    # Scoop needs scripts to be allowed. If the effective policy already allows them
    # (e.g. Bypass for this session) nothing is changed; a policy imposed by a more
    # specific scope or by Group Policy is reported but does not stop the script.
    $allowed = @("Unrestricted", "RemoteSigned", "Bypass")
    if ($allowed -notcontains (Get-ExecutionPolicy).ToString()) {
        try {
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction Stop
        } catch {
            Write-Warning "Execution policy not changed: $($_.Exception.Message)"
        }
    }
    Invoke-RestMethod -Uri "https://get.scoop.sh" | Invoke-Expression
    $env:PATH = "$HOME\scoop\shims;$env:PATH"
}

# git is needed by Scoop to add buckets
scoop install git
scoop bucket add extras

# Tesseract OCR (Main bucket) and the "fast" language models of tesseract-ocr/tessdata_fast,
# stored in ~/.pdftrace/tessdata (searched automatically by PDFTrace).
scoop install tesseract
$tessdata = Join-Path $HOME ".pdftrace\tessdata"
New-Item -ItemType Directory -Force -Path $tessdata | Out-Null
foreach ($lang in ($Languages + @("osd") | Select-Object -Unique)) {
    $target = Join-Path $tessdata "$lang.traineddata"
    Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/tesseract-ocr/tessdata_fast/main/$lang.traineddata" -OutFile $target
    $hash = (Get-FileHash -Algorithm SHA256 $target).Hash
    Write-Host "$lang.traineddata  SHA256 $hash"
}
if ($OcrOnly) {
    Write-Host ""
    Write-Host "Tesseract installed. In PDFTrace open the OCR page and press 'Run OCR'."
    if ($Host.Name -eq "ConsoleHost") { Read-Host "Press Enter to close" | Out-Null }
    exit 0
}

# Main bucket: poppler, qpdf, exiftool, ghostscript, pdftk, pdfcpu. Extras bucket: mupdf (mutool).
$packages = @("qpdf", "exiftool", "ghostscript", "pdftk", "pdfcpu", "mupdf")
if (-not $SkipPoppler) { $packages = @("poppler") + $packages }
scoop install @packages

# pdfid.py and pdf-parser.py (Didier Stevens, public domain) in the folder searched by PDFTrace
$tools = Join-Path $HOME ".pdftrace\tools"
New-Item -ItemType Directory -Force -Path $tools | Out-Null
foreach ($script in @("pdfid.py", "pdf-parser.py")) {
    $target = Join-Path $tools $script
    Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/$script" -OutFile $target
    $hash = (Get-FileHash -Algorithm SHA256 $target).Hash
    Write-Host "$script  SHA256 $hash"
}

Write-Host ""
Write-Host "Not available through Scoop: pdfresurrect, Poppler pdfsig (use WSL if required)."
Write-Host "Open a new terminal (or press 'Re-detect tools' in PDFTrace), then run: pdftrace --check"
if ($Host.Name -eq "ConsoleHost") { Read-Host "Press Enter to close" | Out-Null }
