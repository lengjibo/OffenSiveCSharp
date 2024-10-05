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
    public class InternalStructs32
    {

        [StructLayout(LayoutKind.Sequential)]
        public struct LIST_ENTRY32
        {
            public uint Flink;
            public uint Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PEB_LDR_DATA32
        {
            public uint Length;
            public bool Initialized;
            public uint SsHandle;
            public LIST_ENTRY32 InLoadOrderModuleList;
            public LIST_ENTRY32 InMemoryOrderModuleList;
            public LIST_ENTRY32 InInitializationOrderModuleList;
            public uint EntryInProgress;
            public bool ShutdownInProgress;
            public uint ShutdownThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING32
        {
            public ushort Length;
            public ushort MaximumLength;
            public uint Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LDR_DATA_TABLE_ENTRY32_SNAP
        {
            public LIST_ENTRY32 InLoadOrderLinks;
            public LIST_ENTRY32 InMemoryOrderLinks;
            public LIST_ENTRY32 InInitializationOrderLinks;
            public uint DllBase;
            public uint EntryPoint;
            public uint SizeOfImage;
            public UNICODE_STRING32 FullDllName;
            public UNICODE_STRING32 BaseDllName;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public uint BaseOfData;

            public uint ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public uint SizeOfStackReserve;
            public uint SizeOfStackCommit;
            public uint SizeOfHeapReserve;
            public uint SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS32
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STRING32
        {
            public ushort Length;
            public ushort MaximumLength;
            public uint Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _RTL_DRIVE_LETTER_CURDIR32
        {
            public ushort Flags;
            public ushort Length;
            public int TimeStamp;
            public STRING32 DosPath;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct _CURDIR32
        {
            public UNICODE_STRING32 DosPath;
            public uint Handle;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct RTL_USER_PROCESS_PARAMETERS32
        {
            public uint MaximumLength;
            public uint Length;
            public uint Flags;
            public uint DebugFlags;
            public uint ConsoleHandle;
            public uint ConsoleFlags;
            public uint StandardInput;
            public uint StandardOutput;
            public uint StandardError;
            public _CURDIR32 CurrentDirectory;
            public UNICODE_STRING32 DllPath;
            public UNICODE_STRING32 ImagePathName;
            public UNICODE_STRING32 CommandLine;
            public uint Environment;
            public uint StartingX;
            public uint StartingY;
            public uint CountX;
            public uint CountY;
            public uint CountCharsX;
            public uint CountCharsY;
            public uint FillAttribute;
            public uint WindowFlags;
            public uint ShowWindowFlags;
            public UNICODE_STRING32 WindowTitle;
            public UNICODE_STRING32 DesktopInfo;
            public UNICODE_STRING32 ShellInfo;
            public UNICODE_STRING32 RuntimeData;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public _RTL_DRIVE_LETTER_CURDIR32[] CurrentDirectores;
            public uint EnvironmentSize;
            public uint EnvironmentVersion;
            public uint PackageDependencyData;
            public uint ProcessGroupId;
            public uint LoaderThreads;
            public UNICODE_STRING32 RedirectionDllName;
            public UNICODE_STRING32 HeapPartitionName;
            public uint DefaultThreadpoolCpuSetMasks;
            public uint DefaultThreadpoolCpuSetMaskCount;
            public uint DefaultThreadpoolThreadMaximum;
        }


        public static IntPtr GetLdr32(IntPtr addr)
        {
            return addr + 0xc;
        }

        public static IntPtr GetRTL32(IntPtr addr)
        {
            return addr + 0x10;
        }


    }
}
