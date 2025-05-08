using System;

namespace CookieKatz
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            MainLogic.Run(args);
        }
    }
}


//using System;
//using System.Diagnostics;
//using System.Management;
//using System.Runtime.InteropServices;

//class Program
//{
//    [DllImport("kernel32.dll")]
//    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

//    [DllImport("psapi.dll", SetLastError = true)]
//    static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, out int lpcbNeeded, uint dwFilterFlag);

//    [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
//    static extern uint GetModuleBaseName(IntPtr hProcess, IntPtr hModule, System.Text.StringBuilder lpBaseName, int nSize);

//    [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
//    static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, System.Text.StringBuilder lpFilename, int nSize);
//    [DllImport("kernel32.dll")]
//    static extern bool ReadProcessMemory(
//       IntPtr hProcess,
//       IntPtr lpBaseAddress,
//       [Out] byte[] lpBuffer,
//       int dwSize,
//       out IntPtr lpNumberOfBytesRead);

//    const uint PROCESS_QUERY_INFORMATION = 0x0400;
//    const uint PROCESS_VM_READ = 0x0010;
//    const uint LIST_MODULES_ALL = 0x03;

//    static void Main(string[] args)
//    {
//        string processName = "chrome";
//        string targetModuleName = "chrome.dll";
//        string searchKeyword = "--utility-sub-type=network.mojom.NetworkService";

//        Process[] processes = Process.GetProcessesByName(processName);
//        if (processes.Length == 0)
//        {
//            Console.WriteLine("Không tìm thấy tiến trình.");
//            return;
//        }
//        Process p = null;
//        foreach (var item in processes)
//        {
//            if (GetCommandLineByPid(item.Id).IndexOf(searchKeyword) > -1) {
//                p = item;
//                break;
//            }
//        }

//        IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, p.Id);
//        if (hProcess == IntPtr.Zero)
//        {
//            Console.WriteLine("Không thể mở tiến trình.");
//            return;
//        }

//        IntPtr moduleBase = GetRemoteModuleBaseAddress(hProcess, targetModuleName);
//        if (moduleBase != IntPtr.Zero)
//        {
//            Console.WriteLine($"Base address của module '{targetModuleName}': 0x{moduleBase.ToInt64():X}");
//        }
//        else
//        {
//            Console.WriteLine("Không tìm thấy module.");
//        }
//        FindLargestSection(hProcess, moduleBase);
//    }
//    static string GetCommandLineByPid(int pid)
//    {
//        string query = $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}";
//        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
//        {
//            foreach (ManagementObject obj in searcher.Get())
//            {
//                return obj["CommandLine"]?.ToString();
//            }
//        }
//        return null;
//    }
//    static IntPtr GetRemoteModuleBaseAddress(IntPtr hProcess, string moduleName)
//    {
//        const int MAX_MODULES = 1024;
//        IntPtr[] moduleHandles = new IntPtr[MAX_MODULES];
//        int bytesNeeded;

//        if (EnumProcessModulesEx(hProcess, moduleHandles, moduleHandles.Length * IntPtr.Size, out bytesNeeded, LIST_MODULES_ALL))
//        {
//            int moduleCount = bytesNeeded / IntPtr.Size;
//            var sb = new System.Text.StringBuilder(1024);

//            for (int i = 0; i < moduleCount; i++)
//            {
//                sb.Clear();
//                GetModuleBaseName(hProcess, moduleHandles[i], sb, sb.Capacity);
//                if (string.Equals(sb.ToString(), moduleName, StringComparison.OrdinalIgnoreCase))
//                {
//                    return moduleHandles[i]; // Đây là Base Address của module
//                }
//            }
//        }

//        return IntPtr.Zero;
//    }
//    public static IntPtr FindLargestSection(IntPtr hProcess, IntPtr moduleBase)
//    {
//        // 1. Đọc IMAGE_DOS_HEADER
//        byte[] dosHeaderBytes = new byte[Marshal.SizeOf(typeof(IMAGE_DOS_HEADER))];
//        ReadProcessMemory(hProcess, moduleBase, dosHeaderBytes, dosHeaderBytes.Length, out _);
//        IMAGE_DOS_HEADER dosHeader = ByteArrayToStructure<IMAGE_DOS_HEADER>(dosHeaderBytes);

//        // 2. Lấy địa chỉ NT Headers
//        IntPtr ntHeaderAddress = IntPtr.Add(moduleBase, dosHeader.e_lfanew);

//        // 3. Đọc NumberOfSections từ IMAGE_FILE_HEADER
//        int fileHeaderOffset = 4; // Skip Signature (4 bytes)
//        int fileHeaderSize = Marshal.SizeOf(typeof(IMAGE_FILE_HEADER));
//        byte[] fileHeaderBytes = new byte[fileHeaderSize];
//        ReadProcessMemory(hProcess, IntPtr.Add(ntHeaderAddress, fileHeaderOffset), fileHeaderBytes, fileHeaderSize, out _);
//        IMAGE_FILE_HEADER fileHeader = ByteArrayToStructure<IMAGE_FILE_HEADER>(fileHeaderBytes);

//        ushort sectionCount = fileHeader.NumberOfSections;

//        // 4. Tính offset đến Section Headers
//        int optionalHeaderSize = fileHeader.SizeOfOptionalHeader;
//        IntPtr sectionHeaderPtr = IntPtr.Add(ntHeaderAddress, fileHeaderOffset + fileHeaderSize + optionalHeaderSize);

//        // 5. Lặp qua section headers
//        IMAGE_SECTION_HEADER largestSection = new IMAGE_SECTION_HEADER();
//        uint largestSize = 0;

//        int sectionSize = Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
//        byte[] sectionBytes = new byte[sectionSize];

//        for (int i = 0; i < sectionCount; i++)
//        {
//            IntPtr currentSectionPtr = IntPtr.Add(sectionHeaderPtr, i * sectionSize);
//            ReadProcessMemory(hProcess, currentSectionPtr, sectionBytes, sectionSize, out _);
//            IMAGE_SECTION_HEADER section = ByteArrayToStructure<IMAGE_SECTION_HEADER>(sectionBytes);

//            if (section.VirtualSize > largestSize)
//            {
//                largestSize = section.VirtualSize;
//                largestSection = section;
//            }
//        }

//        // Trả về địa chỉ section lớn nhất
//        return IntPtr.Add(moduleBase, (int)largestSection.VirtualAddress);
//    }
//}
