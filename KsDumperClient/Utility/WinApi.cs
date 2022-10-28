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

        public static readonly uint PROCESS_QUERY_INFORMATION = 0x0400;
        public static readonly uint PROCESS_VM_READ = 0x0010;
        public static readonly uint FALSE = 0;
        public static readonly uint TRUE = 1;
                               
        public static readonly uint MEM_PRIVATE = 0x00020000;
        public static readonly uint MEM_MAPPED = 0x00040000;
        public static readonly uint MEM_IMAGE = 0x01000000;
                               
        public static readonly uint PAGE_NOACCESS = 0x01;
        public static readonly uint PAGE_READONLY = 0x02;
        public static readonly uint PAGE_READWRITE = 0x04;
        public static readonly uint PAGE_WRITECOPY = 0x08;
        public static readonly uint PAGE_EXECUTE = 0x10;
        public static readonly uint PAGE_EXECUTE_READ = 0x20;
        public static readonly uint PAGE_EXECUTE_READWRITE = 0x40;
        public static readonly uint PAGE_EXECUTE_WRITECOPY = 0x80;
        public static readonly uint PAGE_GUARD = 0x100;
        public static readonly uint PAGE_NOCACHE = 0x200;
        public static readonly uint PAGE_WRITECOMBINE = 0x400;

        public static readonly uint MEM_COMMIT = 0x00001000;
        public static readonly uint MEM_RESERVE = 0x00002000;
        public static readonly uint MEM_REPLACE_PLACEHOLDER = 0x00004000;
        public static readonly uint MEM_RESERVE_PLACEHOLDER = 0x00040000;
        public static readonly uint MEM_RESET = 0x00080000;
        public static readonly uint MEM_TOP_DOWN = 0x00100000;
        public static readonly uint MEM_WRITE_WATCH = 0x00200000;
        public static readonly uint MEM_PHYSICAL = 0x00400000;
        public static readonly uint MEM_ROTATE = 0x00800000;
        public static readonly uint MEM_DIFFERENT_IMAGE_BASE_OK = 0x00800000;
        public static readonly uint MEM_RESET_UNDO = 0x01000000;
        public static readonly uint MEM_LARGE_PAGES = 0x20000000;
        public static readonly uint MEM_4MB_PAGES = 0x80000000;
        public static readonly uint MEM_64K_PAGES = (MEM_LARGE_PAGES | MEM_PHYSICAL);
        public static readonly uint MEM_UNMAP_WITH_TRANSIENT_BOOST = 0x00000001;
        public static readonly uint MEM_COALESCE_PLACEHOLDERS = 0x00000001;
        public static readonly uint MEM_PRESERVE_PLACEHOLDER = 0x00000002;
        public static readonly uint MEM_DECOMMIT = 0x00004000;
        public static readonly uint MEM_RELEASE = 0x00008000;
        public static readonly uint MEM_FREE = 0x00010000;



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
            [MarshalAs(UnmanagedType.U4)] uint dwDesiredAccess,
            [MarshalAs(UnmanagedType.U4)] uint bInheritHandle,
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
