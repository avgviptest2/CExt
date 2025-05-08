// ProcessHelper.cs
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace CookieKatz
{
    public static class ProcessHelper
    {
        public static bool GetProcessHandle(uint pid, out IntPtr hProcess)
        {
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (hProcess == IntPtr.Zero || hProcess == new IntPtr(-1))
            {
                Helper.PrintError("OpenProcess failed");
                return false;
            }
            return true;
        }

        public static bool GetProcessName(IntPtr hProcess, out TargetVersion target)
        {
            target = TargetVersion.Chrome;
            StringBuilder processPath = new StringBuilder(260);
            int size = 260;
            if (!QueryFullProcessImageName(hProcess, 0, processPath, ref size))
            {
                Helper.PrintError("QueryFullProcessImageName failed");
                return false;
            }

            string exe = System.IO.Path.GetFileName(processPath.ToString()).ToLower();

            switch (exe)
            {
                case "chrome.exe":
                    target = TargetVersion.Chrome;
                    return true;
                case "msedge.exe":
                    target = TargetVersion.Edge;
                    return true;
                case "msedgewebview2.exe":
                    target = TargetVersion.Webview2;
                    return true;
                default:
                    return false;
            }
        }

        public static bool IsWow64(IntPtr hProcess)
        {
            bool isWow64;
            if (!IsWow64Process(hProcess, out isWow64))
            {
                Helper.PrintError("IsWow64Process failed");
                NativeMethods.CloseHandle(hProcess);
                return true; // assume failure as 32-bit
            }

            if (isWow64)
            {
                NativeMethods.CloseHandle(hProcess);
                return true;
            }

            return false;
        }

        public static bool GetRemoteModuleBaseAddress(IntPtr hProcess, string moduleName, out ulong baseAddr, out uint moduleSize)
        {
            baseAddr = 0;
            moduleSize = 0;

            IntPtr[] modules = new IntPtr[1024];
            uint cbNeeded;
            if (!EnumProcessModulesEx(hProcess, modules, (uint)(IntPtr.Size * modules.Length), out cbNeeded, 0x03))
            {
                Helper.PrintError("EnumProcessModulesEx failed");
                return false;
            }

            int moduleCount = (int)(cbNeeded / (uint)IntPtr.Size);
            for (int i = 0; i < moduleCount; i++)
            {
                StringBuilder modName = new StringBuilder(260);
                if (GetModuleBaseName(hProcess, modules[i], modName, modName.Capacity) == 0)
                    continue;

                if (string.Equals(modName.ToString(), moduleName, StringComparison.OrdinalIgnoreCase))
                {
                    MODULEINFO info;
                    if (!GetModuleInformation(hProcess, modules[i], out info, (uint)Marshal.SizeOf(typeof(MODULEINFO))))
                        return false;

                    baseAddr = (ulong)info.lpBaseOfDll;
                    moduleSize = info.SizeOfImage;
                    return true;
                }
            }
            return false;
        }

        public static bool FindCorrectProcessPID(string processName, out uint pid, out IntPtr hProcess)
        {
            pid = 0;
            hProcess = IntPtr.Zero;

            foreach (Process proc in Process.GetProcessesByName(processName.Replace(".exe", "")))
            {
                try
                {
                    IntPtr handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint)proc.Id);
                    if (handle == IntPtr.Zero)
                        continue;

                    // Placeholder - ideally should inspect PEB or command-line args
                    pid = (uint)proc.Id;
                    hProcess = handle;
                    return true;
                }
                catch { }
            }
            return false;
        }

        public static void FindAllSuitableProcesses(string processName)
        {
            foreach (Process proc in Process.GetProcessesByName(processName.Replace(".exe", "")))
            {
                try
                {
                    IntPtr handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint)proc.Id);
                    if (handle != IntPtr.Zero)
                    {
                        Helper.Print($"[+] Found browser process: {proc.Id}\n");
                        NativeMethods.CloseHandle(handle);
                    }
                }
                catch { }
            }
        }

        #region WinAPI

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process(IntPtr process, out bool wow64);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);

        [DllImport("psapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern uint GetModuleBaseName(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, int nSize);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, [Out] StringBuilder exeName, ref int size);

        [StructLayout(LayoutKind.Sequential)]
        private struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }

        #endregion
    }
}
