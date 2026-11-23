var fso = WScript.CreateObject("Scripting.FileSystemObject");
var shell = WScript.CreateObject("WScript.Shell");
var scriptDir = fso.GetParentFolderName(WScript.ScriptFullName);
var psScript = fso.BuildPath(scriptDir, "server-watchdog.ps1");
var cmd = 'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + psScript + '"';
var exitCode = shell.Run(cmd, 0, true);
WScript.Quit(exitCode);
