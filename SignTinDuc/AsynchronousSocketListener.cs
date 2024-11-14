using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel.Design;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography;

namespace SignTinDuc
{
    public static class AsynchronousSocketListener
    {
        private const int PORT = 9199;
        private const string KEYGUID = "224EAFA6-E888-66DA-99CA-C2AB7DC07B99";
        // quản lý trạng thái chờ và đồng bộ hóa các kết nối socket 
        public static ManualResetEvent allDone = new ManualResetEvent(false);
        //[DllImport("kernel32.dll")]
        //private static extern bool FreeConsole();
        public static void StartListening()
        {
            try
            {
                Socket state = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                Log.WriteActivityLog("Begin Bind Socket", new
                {
                    PORT = 9199
                });
                state.Bind((EndPoint)new IPEndPoint(IPAddress.Any, 9199));
                state.Listen(100);
                Log.WriteActivityLog("Finish Bind Socket", new
                {
                    PORT = 9199
                });
                while (true)
                {
                    AsynchronousSocketListener.allDone.Reset();
                    state.BeginAccept(new AsyncCallback(AsynchronousSocketListener.AcceptCallback), (object)state);
                    AsynchronousSocketListener.allDone.WaitOne();
                }
            }
            catch (Exception ex)
            {
                Log.WriteActivityLog("StartListening: " + ex.ToString(), new
                {
                    PORT = 9199
                });
            }
        }
        private static void AcceptCallback(IAsyncResult ar)
        {
            try
            {
                // set allDone để tiếp tục vòng lặp mới
                AsynchronousSocketListener.allDone.Set();
                Socket socket = ((Socket)ar.AsyncState).EndAccept(ar);
                // tạo 1 đối tượng để lưu trữ dữ liệu nhận từ client
                AsynchronousSocketListener.StateObject state = new AsynchronousSocketListener.StateObject();
                state.workSocket = socket;
                socket.BeginReceive(state.buffer, 0, 10240, SocketFlags.None, new AsyncCallback(AsynchronousSocketListener.ReadCallback), (object)state);
            }
            catch (Exception ex)
            {
                Log.WriteActivityLog("AcceptCallback: " + ex.ToString());
            }
        }
        private static void ReadCallback(IAsyncResult ar)
        {
            AsynchronousSocketListener.StateObject asyncState = (AsynchronousSocketListener.StateObject)ar.AsyncState;
            Socket workSocket = asyncState.workSocket;
            // kiểm tra thông tin khi gửi từ web xuống
            int num1 = workSocket.EndReceive(ar);
            if (num1 <= 0)
                return;
            int num2 = asyncState.sb.Length != 0 ? 1 : 0;
            asyncState.sb.Append(Encoding.ASCII.GetString(asyncState.buffer, 0, num1));
            string content = asyncState.sb.ToString();
            Result result1 = (Result)null;
            Result umnfResultError;
            if (num2 != 0)
            {
                Result result2 = AsynchronousSocketListener.ProcessorPlugin(asyncState.buffer, num1);
                //Console.WriteLine("step1");
                Log.WriteActivityLog("step 1");
                string Message;
                string json = Convertor.ObjectToJson((object)result2, out Message);
                if (json.Length > 0)
                    result2 = Log.ToUMNFResultError(json, ResultStatus.ERROR_CONVERT_DATA, new
                    {
                        result = result2
                    });
                Log.WriteActivityLog("step 2");
                //Console.WriteLine("Step 2");
                byte[] response;
                string frameFromString = Convertor.GetFrameFromString(Message, out response);
                if (frameFromString.Length > 0)
                    umnfResultError = Log.ToUMNFResultError(frameFromString, ResultStatus.ERROR_CONVERT_DATA, new
                    {
                        result = result2
                    });
                //Console.WriteLine("Step 3: send data to client");
                Log.WriteActivityLog(string.Format("step 3: Length data{0}", (object)response.Length));
                workSocket.Send(response);
                //Log.WriteActivityLog("step 4");
                Console.WriteLine("Step 4: End ");
            }
            else
            {
                // khởi tạo phương thức cho quá trình truyền nhận dữ liệu
                string response;
                string responseAsscesConnect = AsynchronousSocketListener.GetResponseAsscesConnect(content, out response);
                if (responseAsscesConnect.Length > 0)
                    result1 = Log.ToUMNFResultError(responseAsscesConnect, ResultStatus.ERROR_ASSCES_CONNECT, new
                    {
                        content = content
                    });
                byte[] buffer = (byte[])null;
                if (result1 == null)
                {
                    string bytes = Convertor.GetBytes(response, out buffer);
                    if (bytes.Length > 0)
                        umnfResultError = Log.ToUMNFResultError(bytes, ResultStatus.ERROR_CONVERT_DATA, new
                        {
                            response = response
                        });
                }
                else
                {
                    string Message;
                    string json = Convertor.ObjectToJson((object)result1, out Message);
                    if (json.Length > 0)
                        result1 = Log.ToUMNFResultError(json, ResultStatus.ERROR_CONVERT_DATA, new
                        {
                            result = result1
                        });
                    string frameFromString = Convertor.GetFrameFromString(Message, out buffer);
                    if (frameFromString.Length > 0)
                        umnfResultError = Log.ToUMNFResultError(frameFromString, ResultStatus.ERROR_CONVERT_DATA, new
                        {
                            result = result1
                        });
                }
                if (!AsynchronousSocketListener.SocketConnected(workSocket))
                    return;
                workSocket.Send(buffer);
            }
            workSocket.BeginReceive(asyncState.buffer, 0, 10240, SocketFlags.None, new AsyncCallback(AsynchronousSocketListener.ReadCallback), (object)asyncState);
        }
        private static Result ProcessorPlugin(byte[] buffer, int bytesRead)
        {
            string data;
            string decodedData = Convertor.GetDecodedData(buffer, bytesRead, out data);
            if (decodedData.Length > 0)
                return Log.ToUMNFResultError(decodedData, ResultStatus.ERROR_INPUT);
            Log.WriteActivityLog("Browser Sent", new
            {
                browserSent = data
            });
            string[] arrData = data.Split('*');
            int result;
            if (!int.TryParse(arrData[0], out result))
                return Log.ToUMNFResultError("FuntionId must be number", ResultStatus.ERROR_INPUT, new
                {
                    funtionId = arrData[0]
                });
            try
            {
                Console.WriteLine("Process Plugin: " + result);
                // lấy ra danh sách các thao tác 
                // 1: kết nối
                // danh sách mã dll từ phía server web ex: vnpt,ncs_6,fpt_ca,.....
                // từ phía client lấy ra các dll quét được trong system32, program file x86
                // sau khi client quét đc file dll => mở popup nhập mật khẩu tiến hành đọc thông tin thiết bị usbtoken(cứ lặp qua các dll cái nào dùng được thì lưu lại) 
                // lấy file certificate của thiết bị kết nối kiểm tra hạn và cảnh báo người dùng
                // 2: ký số
                // kết nối trước đấy đã được lưu 1 lần vào file tạm
                // giả sử cắm 2, 3 thiết bị ?? => trên web đã phải truyền vào thông tin thiết bị ký số xuống client (mã thiết bị) 
                // mỗi lần muốn ký sẽ phải nhập thông tin password
                // 3: trước đấy đã kết nối và quá trình kết nối này vẫn còn
                // khi mà ký số =>




                switch (result)
                {
                    // 1. kết nối đến usbtoken 
                    case 1:
                        //Log.WriteActivityLog("Connect usb token");
                        //return ScanFolderLoadDll.FindPKCS11DLLs(data, arrData);
                    // 2. ký pdf
                    case 2:
                    //return PDFSigner.SignFilePDF(data, arrData);
                    // 3. ký xml
                    case 3:
                    //return Certificate.GetCertBySerial(data, arrData);
                    // 4: thông tin thiết bị
                    case 4:
                        //return Certificate.GetListCert();
                    // 5: ký nhiều file xml
                    case 5:
                    //return XMLSigner.SignFileXML(data, arrData);
                    // 6: ký nhiều file pdf
                    case 6:
                    //return XMLSigner.SignFileXML(data, arrData);
                    // 6: ký nhiều file pdf
                    case 7:
                        //return ResultStatic.ResultOk((object)"1.0.52124");
                    default:
                        return Log.ToUMNFResultError("No define function", ResultStatus.ERROR_INPUT, new
                        {
                            funtionId = result
                        });
                }
            }
            catch (Exception ex)
            {
                return Log.ToUMNFResultError(ex.ToString(), ResultStatus.ERROR, new
                {
                    browserSent = data
                });
            }
        }
        private static string AcceptKey(string key, out string acceptKey)
        {
            acceptKey = (string)null;
            try
            {
                byte[] hash = AsynchronousSocketListener.ComputeHash(key + "224EAFA6-E888-66DA-99CA-C2AB7DC07B99");
                acceptKey = Convert.ToBase64String(hash);
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }
        private static byte[] ComputeHash(string str)
        {
            return SHA1.Create().ComputeHash(Encoding.ASCII.GetBytes(str));
        }

        private static bool SocketConnected(Socket s)
        {
            try
            {
                // kiểm tra kết nối
                // Socket còn kết nối
                if (!(s.Poll(1000, SelectMode.SelectRead) & s.Available == 0))
                    return true;
                // socket đã bị đóng kết nối
                Console.WriteLine("Đóng kết nối socket");
                s.Shutdown(SocketShutdown.Both);
                return false;
            }
            catch
            {
                // Socket đã bị đóng hoặc lỗi xảy ra
                return false;
            }
        }
        private static string GetResponseAsscesConnect(string content, out string response)
        {
            response = "";
            if (content == null)
                return "content is null";
            string[] strArray = content.Replace("ey:", "`").Split('`');
            if (strArray.Length < 2)
                return string.Format("arrContentSplit count = {0}", (object)strArray.Length);
            string acceptKey;
            string responseAsscesConnect = AsynchronousSocketListener.AcceptKey(strArray[1].Replace("\r", "").Split('\n')[0].Trim(), out acceptKey);
            if (responseAsscesConnect.Length > 0)
                return responseAsscesConnect;
            string str = "\r\n";
            response = "HTTP/1.1 101 Switching Protocols" + str + "Upgrade: websocket" + str + "Connection: Upgrade" + str + "Sec-WebSocket-Accept: " + acceptKey + str + str;
            return responseAsscesConnect;
        }
        public class StateObject
        {
            public Socket workSocket;
            public const int BufferSize = 10240;
            public byte[] buffer = new byte[10240];
            public StringBuilder sb = new StringBuilder();
        }
    }
}
