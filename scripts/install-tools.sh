#!/usr/bin/env bash
# PDFTrace - installation of the optional Toolbox tools on Debian/Ubuntu.
# Package names verified on Ubuntu 24.04.
set -euo pipefail

sudo apt-get update
sudo apt-get install -y poppler-utils qpdf mupdf-tools libimage-exiftool-perl pdfresurrect ghostscript pdftk-java \
  tesseract-ocr tesseract-ocr-ita tesseract-ocr-eng

tools="$HOME/.pdftrace/tools"
mkdir -p "$tools"
for script in pdfid.py pdf-parser.py; do
  curl -fsSL -o "$tools/$script" "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/$script"
  sha256sum "$tools/$script"
done

echo
echo "pdfcpu: download the release binary from https://github.com/pdfcpu/pdfcpu/releases and place it in PATH."
echo "Then run: pdftrace --check"
