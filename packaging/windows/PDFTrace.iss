; Inno Setup script for the PDFTrace Windows installer.
; Built by scripts/build_standalone.py --installer (ISCC /DAppVersion=x.y.z).
; Installs per user (no administrator rights), creates the Start menu entry,
; optionally installs the Toolbox tools and starts the GUI at the end.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6F1E2D5C-9B7A-4C3E-8D21-5A4B3C2D1E0F}
AppName=PDFTrace
AppVersion={#AppVersion}
AppPublisher=PDFTrace contributors
AppPublisherURL=https://github.com/OWNER/PDFTrace
DefaultDirName={localappdata}\Programs\PDFTrace
DefaultGroupName=PDFTrace
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\..\dist
OutputBaseFilename=PDFTrace-{#AppVersion}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\..\LICENSE
UninstallDisplayIcon={app}\PDFTrace.exe
ChangesEnvironment=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "italian"; MessagesFile: "compiler:Languages\Italian.isl"

[CustomMessages]
english.ToolsTask=Install the optional analysis tools with Scoop (qpdf, ExifTool, Ghostscript, pdftk, pdfcpu, MuPDF; internet required). Tesseract OCR is already included.
italian.ToolsTask=Installa gli strumenti di analisi facoltativi con Scoop (qpdf, ExifTool, Ghostscript, pdftk, pdfcpu, MuPDF; serve internet). Tesseract OCR è già incluso.
english.PathTask=Add the pdftrace-cli command to PATH
italian.PathTask=Aggiungi il comando pdftrace-cli al PATH
english.ToolsStatus=Installing the optional analysis tools...
italian.ToolsStatus=Installazione degli strumenti di analisi facoltativi...

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addpath"; Description: "{cm:PathTask}"; Flags: unchecked
Name: "tools"; Description: "{cm:ToolsTask}"; Flags: unchecked

[Files]
Source: "..\..\dist\PDFTrace\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\PDFTrace"; Filename: "{app}\PDFTrace.exe"
Name: "{autodesktop}\PDFTrace"; Filename: "{app}\PDFTrace.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addpath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\_internal\scripts\install-tools.ps1"" -SkipPoppler"; StatusMsg: "{cm:ToolsStatus}"; Tasks: tools; Flags: waituntilterminated
Filename: "{app}\PDFTrace.exe"; Description: "{cm:LaunchProgram,PDFTrace}"; Flags: nowait postinstall skipifsilent

[Code]
function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Param) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;
