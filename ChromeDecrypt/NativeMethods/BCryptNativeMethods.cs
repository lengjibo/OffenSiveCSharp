using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static XenoStealer.BCryptInternalStructs;

namespace XenoStealer
{
    public static class BCryptNativeMethods
    {
        private static string BCRYPT_KEY_DATA_BLOB = "KeyDataBlob";

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm,
                                                      [MarshalAs(UnmanagedType.LPWStr)] string pszAlgId,
                                                      [MarshalAs(UnmanagedType.LPWStr)] string pszImplementation,
                                                      uint dwFlags);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint flags);

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptGetProperty(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, IntPtr pbOutput, uint cbOutput, ref uint pcbResult, uint flags);

        [DllImport("bcrypt.dll")]
        internal static extern uint BCryptSetProperty(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, byte[] pbInput, uint cbInput, uint dwFlags);


        [DllImport("bcrypt.dll", EntryPoint = "BCryptImportKey")]
        private static extern uint _BCryptImportKey_KeyDataBlob(IntPtr hAlgorithm,
                                                         IntPtr hImportKey,
                                                         [MarshalAs(UnmanagedType.LPWStr)] string pszBlobType,
                                                         out IntPtr phKey,
                                                         IntPtr pbKeyObject,
                                                         uint cbKeyObject,
                                                         IntPtr pbInput,
                                                         uint cbInput,
                                                         uint dwFlags);

        public static uint BCryptImportKey_KeyDataBlob(IntPtr hAlgorithm,
                                                         IntPtr hImportKey,
                                                         out IntPtr phKey,
                                                         IntPtr pbKeyObject,
                                                         uint cbKeyObject,
                                                         IntPtr pbInput,
                                                         uint cbInput) 
        {
            return _BCryptImportKey_KeyDataBlob(hAlgorithm, hImportKey, BCRYPT_KEY_DATA_BLOB, out phKey, pbKeyObject, cbKeyObject, pbInput, cbInput, 0);
        }

        [DllImport("bcrypt.dll")]
        public static extern uint BCryptDestroyKey(IntPtr hKey);


        [DllImport("bcrypt.dll")]
        internal static extern uint BCryptDecrypt(IntPtr hKey,
                                                  byte[] pbInput,
                                                  uint cbInput,
                                                  ref BCryptInternalStructs.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo,
                                                  byte[] pbIV,
                                                  uint cbIV,
                                                  byte[] pbOutput,
                                                  uint cbOutput,
                                                  ref int pcbResult,
                                                  uint dwFlags);

    }
}
