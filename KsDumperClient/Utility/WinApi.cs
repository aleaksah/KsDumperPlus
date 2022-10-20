using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace KsDumperClient.Utility
{
    public static class WinApi
    {
        public static readonly int FILE_DEVICE_UNKNOWN = 0x22;
        public static readonly int METHOD_BUFFERED = 0x0;
        public static readonly int FILE_ANY_ACCESS = 0x0;

        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        public static readonly int PROCESS_QUERY_INFORMATION = 0x0400;
        public static readonly int PROCESS_VM_READ = 0x0010;
        public static readonly int FALSE = 0;
        public static readonly int TRUE = 1;

        public static readonly int MEM_PRIVATE = 0x00020000;
        public static readonly int MEM_MAPPED = 0x00040000;
        public static readonly int MEM_IMAGE = 0x01000000;

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }


        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr CreateFileA(
            [MarshalAs(UnmanagedType.LPStr)] string filename,
            [MarshalAs(UnmanagedType.U4)] FileAccess access,
            [MarshalAs(UnmanagedType.U4)] FileShare share,
            IntPtr securityAttributes,
            [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
            [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr OpenProcess(
            [MarshalAs(UnmanagedType.U4)] int dwDesiredAccess,
            [MarshalAs(UnmanagedType.U4)] int bInheritHandle,
            [MarshalAs(UnmanagedType.U4)] int dwProcessId
            );

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength); 

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode,
            IntPtr lpInBuffer, int nInBufferSize,
            IntPtr lpOutBuffer, int nOutBufferSize,
            IntPtr lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll")]
        public static extern int GetLongPathName(string path, StringBuilder pszPath, int cchPath);
    }
}
