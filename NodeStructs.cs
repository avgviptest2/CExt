// NodeStructs.cs
using System;
using System.Runtime.InteropServices;

namespace CookieKatz.Structs
{
    [StructLayout(LayoutKind.Sequential)]
    public struct RootNode
    {
        public ulong beginNode;
        public ulong firstNode;
        public UIntPtr size;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct Node
    {
        public ulong left;
        public ulong right;
        public ulong parent;
        [MarshalAs(UnmanagedType.U1)]
        public bool is_black;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
        public byte[] padding;

        public OptimizedString key;
        public ulong valueAddress;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OptimizedString
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 23)]
        public byte[] buf;
        public byte len;
    }
}
