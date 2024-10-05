using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static XenoStealer.InternalStructs;
using static XenoStealer.InternalStructs64;

namespace XenoStealer
{
    public class SpecialNativeMethods
    {
        [DllImport("ntdll.dll", SetLastError = true, EntryPoint = "NtWow64QueryInformationProcess64")]
        public static extern int NtQueryPBI64From32(
            IntPtr ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            ref PROCESS_BASIC_INFORMATION64 ProcessInformation,
            uint BufferSize,
            ref uint NumberOfBytesRead);

        [DllImport("ntdll.dll", SetLastError = true, EntryPoint = "NtWow64ReadVirtualMemory64")]
        public static extern int ReadProcessMemory64From32(
            IntPtr ProcessHandle,
            ulong BaseAddress,
            IntPtr Buffer,
            ulong BufferSize,
            ref ulong NumberOfBytesWritten);


        [DllImport("ntdll.dll", SetLastError = true, EntryPoint = "NtWow64WriteVirtualMemory64")]
        public static extern int WriteProcessMemory64From32(
            IntPtr ProcessHandle,
            ulong BaseAddress,
            IntPtr Buffer,
            ulong BufferSize,
            ref ulong NumberOfBytesWritten);


    }
}
