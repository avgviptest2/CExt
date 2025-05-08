// NativeMethods.cs
using System;
using System.Runtime.InteropServices;

public static class NativeMethods
{
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}
