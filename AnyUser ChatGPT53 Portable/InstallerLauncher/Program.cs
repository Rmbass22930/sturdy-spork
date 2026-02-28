using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace InstallerLauncher;

internal static class Program
{
    private const string ScriptName = "install-anyuser-chatgpt53.ps1";

    public static int Main(string[] args)
    {
        var baseDir = AppContext.BaseDirectory;
        var scriptPath = Path.Combine(baseDir, ScriptName);

        if (!File.Exists(scriptPath))
        {
            Console.Error.WriteLine($"Installer script not found next to launcher: {scriptPath}");
            return 2;
        }

        var forwardedArgs = BuildArgumentTail(args);
        var argumentBuilder = new StringBuilder();
        argumentBuilder.Append("-NoProfile -ExecutionPolicy Bypass -File ");
        argumentBuilder.Append(Quote(scriptPath));
        if (forwardedArgs.Length > 0)
        {
            argumentBuilder.Append(' ');
            argumentBuilder.Append(forwardedArgs);
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = argumentBuilder.ToString(),
            WorkingDirectory = baseDir,
            UseShellExecute = true,
            Verb = "runas"
        };

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                Console.Error.WriteLine("Failed to launch PowerShell for installer.");
                return 3;
            }
            process.WaitForExit();
            return process.ExitCode;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            Console.Error.WriteLine("Installer cancelled: Administrator approval was declined.");
            return 1223;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failed to start installer: {ex.Message}");
            return 4;
        }
    }

    private static string BuildArgumentTail(string[] args)
    {
        if (args.Length == 0)
        {
            return string.Empty;
        }

        var builder = new StringBuilder();
        for (var i = 0; i < args.Length; i++)
        {
            if (i > 0)
            {
                builder.Append(' ');
            }
            builder.Append(Quote(args[i]));
        }
        return builder.ToString();
    }

    private static string Quote(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "\"\"";
        }

        if (value.Contains(' ') || value.Contains('"'))
        {
            var escaped = value.Replace("\"", "\\\"");
            return $"\"{escaped}\"";
        }

        return value;
    }
}
