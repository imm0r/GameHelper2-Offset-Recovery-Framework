# Publishes the WPF GUI as a single self-contained win-x64 executable.
# Output: gui/PoEformance.Gui/bin/Release/net10.0-windows/win-x64/publish/PoEformance.Gui.exe
# Run from the PoEformance/ folder:  ./publish-gui.ps1

dotnet publish gui/PoEformance.Gui -c Release -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true

Write-Host ""
Write-Host "Published to: gui/PoEformance.Gui/bin/Release/net10.0-windows/win-x64/publish/"
