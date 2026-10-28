# PDFTrace

PDFTrace è un'applicazione open source per l'analisi forense dei file PDF. Il PDF viene aperto in sola
lettura ed esaminato da una serie di moduli di analisi; i risultati sono raccolti in un'interfaccia
desktop, in uno strumento a riga di comando e in report esportabili.

## Cosa analizza

| Ambito | Contenuto |
|---|---|
| File | SHA-256, SHA-1, MD5 |
| Metadati | dizionario Info, XMP, confronto Info/XMP, revisioni precedenti |
| Struttura | revisioni, xref, trailer, oggetti ridefiniti, script e azioni (non eseguiti) |
| Font | inventario (pdffonts), programmi dei font incorporati (fontTools), date di build dei font |
| Immagini | inventario, anteprima ed estrazione (pdfimages) |
| Testo e layout | testo, parole, coordinate, oggetti per pagina, Page Inspector |
| OCR | riconoscimento del testo delle pagine con Tesseract e confronto con il livello di testo: testo presente nel file ma non visibile, testo visibile ma assente dal livello estraibile |
| Livello di testo | testo invisibile o coperto, testo fuori pagina, testo sovrapposto, cambi di font nella riga |
| Oggetti | inventario di oggetti e stream, livelli, segnalibri, miniature, dati applicativi (PieceInfo) |
| Contenuti interattivi | annotazioni con autori e date, link, JavaScript (come testo), campi modulo, allegati |
| Firme | dizionari di firma, certificati, dati aggiunti dopo la firma |
| Metadati delle immagini | EXIF, GPS, XMP, IPTC e ICC nelle immagini incorporate, stima della qualità JPEG |
| Confronto tra parser | gli stessi dati letti da pdfminer, pikepdf, pypdf e PDFium |
| Rilievi | indicatori INFO / NOTICE / WARNING con evidenze, cronologia di tutte le date |
| Toolbox | strumenti open source di terze parti eseguiti sullo stesso file (vedi sotto) |
| Report | JSON, CSV, Markdown, HTML |

## Download e Installazion (Windows)

- `PDFTrace-<versione>-setup.exe`: programma di installazione. Non richiede diritti di amministratore;
  al termine avvia l'interfaccia. Le opzioni facoltative installano gli strumenti della Toolbox e
  aggiungono `pdftrace-cli` al `PATH`.
- `PDFTrace-<versione>-windows-portable.zip`: lo stesso programma in una cartella, avviabile con
  `PDFTrace.exe` senza installazione.

Python, le librerie, Poppler, pdfid e pdf-parser sono inclusi. 

## Installazione dai sorgenti

### Requisiti

- Python 3.12 o successivo
- Poppler (pdfinfo, pdffonts, pdfimages)
- Facoltativi: gli strumenti della Toolbox (script di installazione in `scripts/`)

### Procedura

**Windows (PowerShell)**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[gui]"
```
**Linux**

```bash
sudo apt install poppler-utils
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[gui]"
```

**macOS**

```bash
brew install poppler
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[gui]"
```

Su Windows Poppler è disponibile nelle release di
[poppler-windows](https://github.com/oschwartz10612/poppler-windows/releases) oppure con
`conda install -c conda-forge poppler`. La cartella `Library\bin` va aggiunta al `PATH` oppure indicata
con la variabile `PDFTRACE_POPPLER_PATH`. Nel prompt dei comandi l'ambiente si attiva con
`.venv\Scripts\activate.bat`. 
Se PowerShell blocca lo script: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.

Gli strumenti facoltativi si installano con `scripts/install-tools.ps1` (Windows, tramite
[Scoop](https://scoop.sh), che li aggiunge anche al `PATH`) oppure con `scripts/install-tools.sh`
(Debian/Ubuntu).

La configurazione si verifica con:

```bash
pdftrace --check
```

## Utilizzo

Interfaccia desktop:

```bash
pdftrace-gui
```

Riga di comando:

```bash
pdftrace documento.pdf
pdftrace documento.pdf --html report.html --json report.json
pdftrace documento.pdf --tools all --tool-output ./output-strumenti
pdftrace documento.pdf --extract-images ./immagini --extract-attachments ./allegati
pdftrace documento.pdf --ocr --ocr-lang ita+eng --ocr-text ocr.txt
pdftrace --list-tools
```

## OCR

La pagina OCR esegue il riconoscimento ottico dei caratteri con Tesseract. Ogni pagina viene resa come
immagine, senza eseguire script, e il testo riconosciuto viene confrontato per posizione con il livello
di testo del PDF. Sono così evidenziati il testo presente nel file ma non visibile nella pagina (testo
bianco, minuscolo, coperto o fuori pagina) e il testo visibile che non compare nel livello estraibile
(scansioni, testo inserito come immagine). Lingue, risoluzione e numero massimo di pagine sono
selezionabili; il testo riconosciuto può essere esportato.

Nell'eseguibile per Windows Tesseract è incluso con i modelli per italiano e inglese. Nell'installazione
dai sorgenti Tesseract si installa con `scripts/install-tools.ps1 -OcrOnly` (Windows) oppure con
`sudo apt install tesseract-ocr tesseract-ocr-ita` (Debian/Ubuntu). Il programma cerca Tesseract nella
cartella dell'applicazione, nel `PATH` e nelle cartelle di installazione abituali; il percorso può
essere indicato con la variabile `PDFTRACE_TESSERACT` e i modelli linguistici con `PDFTRACE_TESSDATA`.

## Toolbox
Altri strumenti possono essere aggiunti nel file di configurazione.

## Documentazione
- [Sicurezza](SECURITY.md)
- [Come contribuire](CONTRIBUTING.md)

## Limiti

- Metadati, date e dati dei font possono essere scritti o modificati da un software.
- Le parole chiave all'interno degli object stream compressi non sono conteggiate dalla scansione
  interna (pdfid e qpdf coprono questo caso).
- Le date numeriche nel testo sono lette come giorno/mese/anno.
- Le firme digitali vengono rilevate; la validazione è demandata a pdfsig.

## Licenza

Apache License 2.0. Vedere [LICENSE](LICENSE) e [NOTICE](NOTICE).
