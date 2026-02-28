using System.Diagnostics;

var scriptPath = @"H:\gdrive\logincodex.ps1";
var args = $"-NoProfile -ExecutionPolicy Bypass -File \"{scriptPath}\"";

var psi = new ProcessStartInfo("powershell.exe", args)
{
    UseShellExecute = false
};

using var proc = Process.Start(psi);
if (proc is null)
{
    return 1;
}

proc.WaitForExit();
return proc.ExitCode;
