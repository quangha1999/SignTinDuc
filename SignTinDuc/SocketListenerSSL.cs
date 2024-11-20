using System;
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
            //string certPath = "E:\\SourceCode\\SignSSL\\SignSSL\\certificate.pfx";
            //string certPassword = "12345678";

            //// Tải chứng chỉ SSL
            //var cert = new X509Certificate2(certPath, certPassword);

            // Tạo HttpListener
            listener = new HttpListener();
            listener.Prefixes.Add("http://localhost:9199/");
            listener.Start();
            listenTask = Task.Run(() => ListenForClients());
        }
        private static async Task ListenForClients()
        {
            //SSL
            //while (true)
            //{
            //    HttpListenerContext context = listener.GetContext();
            //    if (context.Request.IsWebSocketRequest)
            //    {
            //        HandleWebSocket(context, cert);
            //    }
            //    else
            //    {
            //        context.Response.StatusCode = 400;
            //        context.Response.Close();
            //    }
            //}
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
                Console.WriteLine("WebSocket connection established.");
            }
            catch (Exception e)
            {
                Console.WriteLine($"WebSocket error: {e.Message}");
                context.Response.StatusCode = 500;
                context.Response.Close();
                return;
            }

            WebSocket webSocket = wsContext.WebSocket;

            byte[] buffer = new byte[1024];
            while (webSocket.State == WebSocketState.Open)
            {
                WebSocketReceiveResult result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);

                if (result.MessageType == WebSocketMessageType.Close)
                {
                    await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closed by the server", CancellationToken.None);
                    Console.WriteLine("WebSocket connection closed.");
                }
                else if (result.MessageType == WebSocketMessageType.Text)
                {
                    string message = Encoding.UTF8.GetString(buffer, 0, result.Count);
                    Console.WriteLine($"Received: {message}");

                    // Echo message back to client
                    string response = $"Server: {message}";
                    byte[] responseBytes = Encoding.UTF8.GetBytes(response);
                    await webSocket.SendAsync(new ArraySegment<byte>(responseBytes), WebSocketMessageType.Text, true, CancellationToken.None);
                }
            }
        }
        #endregion
    }
}
