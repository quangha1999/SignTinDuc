using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SignTinDuc
{
    public class CreateSocket
    {
        private const int PORT = 9199;
        private const string KEYGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        // quản lý trạng thái chờ và đồng bộ hóa các kết nối socket 
        public static ManualResetEvent allDone = new ManualResetEvent(false);
        //[DllImport("kernel32.dll")]
        //private static extern bool FreeConsole();

    }
}
