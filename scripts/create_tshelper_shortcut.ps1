param(
    [Parameter(Mandatory = $true)]
    [string]$RootPath
)

$ErrorActionPreference = "Stop"
$root = [System.IO.Path]::GetFullPath($RootPath)
$pythonw = Join-Path $root ".venv\Scripts\pythonw.exe"
$icon = Join-Path $root "assets\ts-logo.ico"

if (-not (Test-Path -LiteralPath $pythonw -PathType Leaf)) {
    throw "Virtual environment pythonw.exe was not found: $pythonw"
}
if (-not (Test-Path -LiteralPath $icon -PathType Leaf)) {
    throw "TSHelper icon was not found: $icon"
}

$programs = [Environment]::GetFolderPath("Programs")
if (-not $programs) {
    throw "Windows Start Menu directory was not found"
}

$shortcutPath = Join-Path $programs "TSHelper.lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $pythonw
$shortcut.Arguments = "-m tshelper"
$shortcut.WorkingDirectory = $root
$shortcut.IconLocation = "$icon,0"
$shortcut.Description = "TSHelper"
$shortcut.WindowStyle = 1
$shortcut.Save()
[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shortcut)
[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)
$shortcut = $null
$shell = $null

# AppUserModelID связывает закреплённый ярлык с окном pythonw.exe, запущенным TSHelper.
$appId = "Et0ZheMax.TSHelper"
$propertySetterSource = @'
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

public static class ShortcutAppId
{
    [ComImport, Guid("00021401-0000-0000-C000-000000000046")]
    private class ShellLink { }

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99")]
    private interface IPropertyStore
    {
        uint GetCount(out uint count);
        uint GetAt(uint index, out PropertyKey key);
        uint GetValue(ref PropertyKey key, out PropVariant value);
        uint SetValue(ref PropertyKey key, ref PropVariant value);
        uint Commit();
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct PropertyKey
    {
        public Guid FormatId;
        public uint PropertyId;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct PropVariant
    {
        [FieldOffset(0)] public ushort VariantType;
        [FieldOffset(8)] public IntPtr PointerValue;
    }

    [DllImport("ole32.dll")]
    private static extern int PropVariantClear(ref PropVariant value);

    public static void Set(string shortcutPath, string appId)
    {
        var link = new ShellLink();
        ((IPersistFile)link).Load(shortcutPath, 2);
        var store = (IPropertyStore)link;
        var key = new PropertyKey {
            FormatId = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3"),
            PropertyId = 5
        };
        var value = new PropVariant {
            VariantType = 31,
            PointerValue = Marshal.StringToCoTaskMemUni(appId)
        };
        try {
            Marshal.ThrowExceptionForHR((int)store.SetValue(ref key, ref value));
            Marshal.ThrowExceptionForHR((int)store.Commit());
            ((IPersistFile)link).Save(shortcutPath, true);
        }
        finally {
            PropVariantClear(ref value);
            Marshal.FinalReleaseComObject(link);
        }
    }
}
'@

if (-not ("ShortcutAppId" -as [type])) {
    Add-Type -TypeDefinition $propertySetterSource
}
[ShortcutAppId]::Set($shortcutPath, $appId)
