// CookieStructs.cs
using System;
using System.Runtime.InteropServices;

namespace CookieKatz.Structs
{
    public enum CookiePriority
    {
        COOKIE_PRIORITY_LOW = 0,
        COOKIE_PRIORITY_MEDIUM = 1,
        COOKIE_PRIORITY_HIGH = 2,
    }

    public enum CookieSameSite
    {
        UNSPECIFIED = -1,
        NO_RESTRICTION = 0,
        LAX_MODE = 1,
        STRICT_MODE = 2
    }

    public enum CookieSourceScheme
    {
        kUnset = 0,
        kNonSecure = 1,
        kSecure = 2
    }

    public enum CookieSourceType
    {
        kUnknown = 0,
        kHTTP = 1,
        kScript = 2,
        kOther = 3
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RemoteVector
    {
        public ulong begin_;
        public ulong end_;
        public ulong unk;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessBoundString
    {
        public RemoteVector maybe_encrypted_data_;
        public ulong original_size_;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] unk;
        [MarshalAs(UnmanagedType.U1)]
        public bool encrypted_;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct CanonicalCookieChrome130
    {
        public ulong _vfptr;
        public OptimizedString name;
        public OptimizedString domain;
        public OptimizedString path;
        public long creation_date;
        [MarshalAs(UnmanagedType.U1)]
        public bool secure;
        [MarshalAs(UnmanagedType.U1)]
        public bool httponly;
        public CookieSameSite same_site;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] partition_key;
        public CookieSourceScheme source_scheme;
        public int source_port;
        public OptimizedString value;
        public long expiry_date;
        public long last_access_date;
        public long last_update_date;
        public CookiePriority priority;
        public CookieSourceType source_type;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct CanonicalCookieEdge130
    {
        public ulong _vfptr;
        public OptimizedString name;
        public OptimizedString domain;
        public OptimizedString path;
        public long creation_date;
        [MarshalAs(UnmanagedType.U1)]
        public bool secure;
        [MarshalAs(UnmanagedType.U1)]
        public bool httponly;
        public CookieSameSite same_site;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 136)]
        public byte[] partition_key;
        public CookieSourceScheme source_scheme;
        public int source_port;
        public OptimizedString value;
        public long expiry_date;
        public long last_access_date;
        public long last_update_date;
        public CookiePriority priority;
        public CookieSourceType source_type;
    }
}
