using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static XenoStealer.InternalStructs;

namespace XenoStealer
{
    public class InternalStructs64
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION64
        {
            public int ExitStatus;
            public ulong PebBaseAddress;
            public ulong AffinityMask;
            public uint BasePriority;
            public ulong UniqueProcessId;
            public ulong InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]

        public struct LIST_ENTRY64
        {
            public ulong Flink;
            public ulong Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PEB_LDR_DATA64
        {
            public uint Length;
            public bool Initialized;
            public ulong SsHandle;
            public LIST_ENTRY64 InLoadOrderModuleList;
            public LIST_ENTRY64 InMemoryOrderModuleList;
            public LIST_ENTRY64 InInitializationOrderModuleList;
            public ulong EntryInProgress;
            public bool ShutdownInProgress;
            public ulong ShutdownThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]

        public struct UNICODE_STRING64
        {
            public ushort Length;
            public ushort MaximumLength;
            public ulong Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STRING64
        {
            public ushort Length;
            public ushort MaximumLength;
            public ulong Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LDR_DATA_TABLE_ENTRY64_SNAP
        {
            public LIST_ENTRY64 InLoadOrderLinks;
            public LIST_ENTRY64 InMemoryOrderLinks;
            public LIST_ENTRY64 InInitializationOrderLinks;
            public ulong DllBase;
            public ulong EntryPoint;
            public uint SizeOfImage;
            public UNICODE_STRING64 FullDllName;
            public UNICODE_STRING64 BaseDllName;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;

            public ulong ImageBase;
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
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }



        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS64
        {
            public uint Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct _RTL_DRIVE_LETTER_CURDIR
        {
            public ushort Flags;
            public ushort Length;
            public int TimeStamp;
            public STRING64 DosPath;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct _CURDIR
        {
            public UNICODE_STRING64 DosPath;
            public ulong Handle;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct RTL_USER_PROCESS_PARAMETERS64
        {
            public uint MaximumLength;
            public uint Length;
            public uint Flags;
            public uint DebugFlags;
            public ulong ConsoleHandle;
            public uint ConsoleFlags;
            public ulong StandardInput;
            public ulong StandardOutput;
            public ulong StandardError;
            public _CURDIR CurrentDirectory;
            public UNICODE_STRING64 DllPath;
            public UNICODE_STRING64 ImagePathName;
            public UNICODE_STRING64 CommandLine;
            public ulong Environment;
            public uint StartingX;
            public uint StartingY;
            public uint CountX;
            public uint CountY;
            public uint CountCharsX;
            public uint CountCharsY;
            public uint FillAttribute;
            public uint WindowFlags;
            public uint ShowWindowFlags;
            public UNICODE_STRING64 WindowTitle;
            public UNICODE_STRING64 DesktopInfo;
            public UNICODE_STRING64 ShellInfo;
            public UNICODE_STRING64 RuntimeData;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public _RTL_DRIVE_LETTER_CURDIR[] CurrentDirectores;
            public ulong EnvironmentSize;
            public ulong EnvironmentVersion;
            public ulong PackageDependencyData;
            public uint ProcessGroupId;
            public uint LoaderThreads;
            public UNICODE_STRING64 RedirectionDllName;
            public UNICODE_STRING64 HeapPartitionName;
            public ulong DefaultThreadpoolCpuSetMasks;
            public uint DefaultThreadpoolCpuSetMaskCount;
            public uint DefaultThreadpoolThreadMaximum;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID64
        {
            public ulong UniqueProcess;
            public ulong UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class THREAD_BASIC_INFORMATION64
        {
            public uint ExitStatus;
            public ulong TebBaseAddress;
            public CLIENT_ID64 ClientId;
            public ulong AffinityMask;
            public int Priority;
            public int BasePriority;
        }


        public static ulong GetLdr64(ulong addr)
        {
            return addr + 0x18;
        }

        public static ulong GetRTL64(ulong addr)
        {
            return addr + 0x20;
        }

    }
}
