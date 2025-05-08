// VersionHelper.cs
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace CookieKatz
{
    public static class VersionHelper
    {
        public static bool GetBrowserVersion(IntPtr hProcess, out BrowserVersion version)
        {
            version = new BrowserVersion();

            StringBuilder path = new StringBuilder(260);
            int size = path.Capacity;
            if (!QueryFullProcessImageName(hProcess, 0, path, ref size))
            {
                Helper.PrintError("QueryFullProcessImageName failed");
                return false;
            }

            string exePath = path.ToString();
            if (!File.Exists(exePath))
            {
                Helper.Print("[-] File not found: " + exePath + "\n");
                return false;
            }

            try
            {
                FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(exePath);
                version.highMajor = (ushort)fvi.FileMajorPart;
                version.highMinor = (ushort)fvi.FileMinorPart;
                version.lowMajor = (ushort)fvi.FileBuildPart;
                version.lowMinor = (ushort)fvi.FilePrivatePart;
                return true;
            }
            catch (Exception ex)
            {
                Helper.Print("[-] Exception while reading version: " + ex.Message + "\n");
                return false;
            }
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder exeName, ref int size);
    }
}
