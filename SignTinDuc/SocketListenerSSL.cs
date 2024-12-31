using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SignTinDuc
{
    public static class SocketListenerSSL
    {
        private static HttpListener listener;
        private static Task listenTask;

        public static void ConnectListener()
        {
            listener = new HttpListener();
            listener.Prefixes.Add("http://localhost:9199/");
            listener.Start();
            listenTask = Task.Run(() => ListenForClients());
        }
        private static async Task ListenForClients()
        {
            // NO SSL
            while (true)
            {
                // Chờ yêu cầu kết nối WebSocket
                HttpListenerContext context = await listener.GetContextAsync();
                if (context.Request.IsWebSocketRequest)
                {
                    ProcessWebSocketRequest(context);
                }
                else
                {
                    context.Response.StatusCode = 400;
                    context.Response.Close();
                }
            }
        }
        #region SSL
        private static async void HandleWebSocket(HttpListenerContext context, X509Certificate2 cert)
        {
            var webSocketContext = await context.AcceptWebSocketAsync(null);

            Console.WriteLine("Kết nối WebSocket đã được thiết lập.");
            var webSocket = webSocketContext.WebSocket;

            byte[] buffer = new byte[1024];
            while (webSocket.State == System.Net.WebSockets.WebSocketState.Open)
            {
                var result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), System.Threading.CancellationToken.None);
                string receivedMessage = Encoding.UTF8.GetString(buffer, 0, result.Count);
                Console.WriteLine($"Nhận từ client: {receivedMessage}");

                byte[] responseMessage = Encoding.UTF8.GetBytes("Server đã nhận: " + receivedMessage);
                await webSocket.SendAsync(new ArraySegment<byte>(responseMessage), System.Net.WebSockets.WebSocketMessageType.Text, true, System.Threading.CancellationToken.None);
            }
        }
        #endregion
        #region
        //NoSSL
        private static async void ProcessWebSocketRequest(HttpListenerContext context)
        {
            WebSocketContext wsContext = null;

            try
            {
                wsContext = await context.AcceptWebSocketAsync(subProtocol: null);
                Console.WriteLine("WebSocket connection .");
            }
            catch (Exception e)
            {
                Console.WriteLine($"WebSocket error: {e.Message}");
                context.Response.StatusCode = 500;
                context.Response.Close();
                return;
            }

            WebSocket webSocket = wsContext.WebSocket;

            byte[] buffer = new byte[1024 * 8];
            StringBuilder receivedMessage = new StringBuilder();

            try
            {
                while (webSocket.State == WebSocketState.Open)
                {
                    WebSocketReceiveResult result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);

                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closed by the server", CancellationToken.None);

                    }
                    else if (result.MessageType == WebSocketMessageType.Text)
                    {
                        // Lưu dữ liệu đã nhận vào StringBuilder để ghép nối nếu nhận dữ liệu phân mảnh
                        receivedMessage.Append(Encoding.UTF8.GetString(buffer, 0, result.Count));

                        // Kiểm tra nếu đã nhận hết thông điệp
                        if (result.EndOfMessage)
                        {
                            string message = receivedMessage.ToString();

                            // Xử lý theo mã lệnh truyền vào
                            var rss = new Result();
                            if (!string.IsNullOrEmpty(message))
                            {
                                var res = JsonConvert.DeserializeObject<DataJson>(message);
                                rss = ProcessorPlugin(res);
                            }

                            // Echo message back to client
                            byte[] responseBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(rss));
                            await webSocket.SendAsync(new ArraySegment<byte>(responseBytes), WebSocketMessageType.Text, true, CancellationToken.None);

                            // Reset StringBuilder để nhận dữ liệu tiếp theo
                            receivedMessage.Clear();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                await webSocket.CloseAsync(WebSocketCloseStatus.InternalServerError, "Lỗi websocket", CancellationToken.None);
            }
        }
        #endregion
        #region xử lý nghiệp vụ
        private static Result ProcessorPlugin(DataJson jsondata)
        {
            try
            {
                //Console.WriteLine("Process Plugin: " + result);

                switch (jsondata.action)
                {
                    // 1. Kiểm tra kết nối đến usbtoken 
                    case 1:
                    //return ConnectUsbToken.GetUsbTokenInformation(arrData);
                    // 2. Lấy danh sách chứng thư số
                    case 2:
                        return ConnectUsbToken.GetInformationDevices(jsondata.dll, jsondata.data, jsondata.messageId);
                    // 3. ký pdf
                    case 4:
                    //return ConnectUsbToken.SignPdfUsbToken(arrData);
                    // 4: ký xml
                    case 3:
                        return ConnectUsbToken.SignXmlUsbToken(jsondata.dll, jsondata.serial, jsondata.data, jsondata.messageId);
                    // 5: ký nhiều file xml
                    case 5:
                        return ConnectUsbToken.SignMultipleFileXML(jsondata.dll, jsondata.serial, jsondata.data, jsondata.messageId);
                    // 6: ký nhiều file pdf
                    case 6:
                    //return XMLSigner.SignFileXML(data, arrData);
                    // 6: ký nhiều file pdf
                    case 7:
                    //return Certificate.GetListCert();
                    default:
                        return Log.ToUMNFResultError("No define function", ResultStatus.ERROR_INPUT, new
                        {
                            funtionId = ""
                        });
                }
            }
            catch (Exception ex)
            {
                return Log.ToUMNFResultError(ex.ToString(), ResultStatus.ERROR, new
                {
                    browserSent = ""
                });
            }
        }
        #endregion
        #region 
        public class DataJson
        {
            public int action { get; set; }
            public string? dll { get; set; }
            public string? serial { get; set; }
            public string? data { get; set; }
            public string? messageId { get; set; }
        }
        #endregion
    }
}
