# Publishes the WPF GUI as a single self-contained win-x64 executable.
# Output: gui/OffsetRecovery.Gui/bin/Release/net10.0-windows/win-x64/publish/OffsetRecovery.Gui.exe
# Run from the standalone/ folder:  ./publish-gui.ps1

dotnet publish gui/OffsetRecovery.Gui -c Release -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true

Write-Host ""
Write-Host "Published to: gui/OffsetRecovery.Gui/bin/Release/net10.0-windows/win-x64/publish/"
