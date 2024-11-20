namespace SignTinDuc
{
    public static class Program
    {
        /// <summary>
        ///  The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            // chỉ chạy socket ngầm
            bool showForm = false;
            if (showForm)
            {
                ApplicationConfiguration.Initialize();
                Application.Run(new LoginForm());
            }
            else
            {
                SocketListenerSSL.ConnectListener();
                // Đảm bảo ứng dụng không kết thúc ngay
                Thread.Sleep(Timeout.Infinite);
            }
        }
    }
}