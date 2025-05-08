// Helper.cs
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class Helper
{
    [DllImport("kernel32.dll")]
    private static extern uint GetLastError();

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint FormatMessage(
        uint dwFlags, IntPtr lpSource, uint dwMessageId, uint dwLanguageId,
        out IntPtr lpBuffer, uint nSize, IntPtr Arguments);

    private const uint FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100;
    private const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
    private const uint FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;

    public static void ConvertToByteArray(ulong value, byte[] byteArray, int size)
    {
        for (int i = 0; i < size; ++i)
        {
            byteArray[i] = (byte)(value & 0xFF);
            value >>= 8;
        }
    }

    public static string GetLastErrorAsString()
    {
        uint errorCode = GetLastError();
        if (errorCode == 0)
            return "";
        IntPtr buffer;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            IntPtr.Zero, errorCode, 0, out buffer, 0, IntPtr.Zero);

        string message = Marshal.PtrToStringUni(buffer);
        LocalFree(buffer);
        return message;
    }

    public static void PrintError(string message)
    {
        string error = GetLastErrorAsString();
        Console.WriteLine($"[ERROR] {message}, Error: {error}");
    }

    public static void Print(string message)
    {
        Console.Write(message);
    }

    public static void PrintLine(string message)
    {
        Console.WriteLine(message);
    }

    public static void DebugPrint(string message)
    {
#if DEBUG
        Console.WriteLine("[DEBUG] " + message);
#endif
    }
}
