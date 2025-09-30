; Script Inno Setup để tạo installer cho ứng dụng WinForms

[Setup]
AppName=TinDucSignService
AppVersion=1.0
DefaultDirName={localappdata}\TinDucSign
DefaultGroupName=TinDucSign
OutputDir=D:\Code\2025\SignTinDuc\BuildSetup\Installer
OutputBaseFilename=Setup_TinDucSign
Compression=lzma
SolidCompression=yes

[Files]
Source: "D:\Code\2025\SignTinDuc\BuildSetup\Output\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\TinDucSign"; Filename: "{app}\SignTinDuc.exe"
Name: "{commondesktop}\TinDucSignServices"; Filename: "{app}\SignTinDuc.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Tạo shortcut ngoài màn hình"; GroupDescription: "Tùy chọn thêm:"

[Run]
Filename: "{app}\SignTinDuc.exe"; Description: "Chạy công cụ ký số TinDucSignService"; Flags: nowait postinstall skipifsilent
