using Microsoft.Win32;

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
            // Luôn khởi động socket ngay khi ứng dụng chạy
            Task.Run(() => SocketListenerSSL.ConnectListener());
            Application.Run(new TrayApplicationContext());
            //bool showForm = false;
            //if (showForm)
            //{
            //    ApplicationConfiguration.Initialize();
            //    Application.Run(new LoginForm());
            //}
            //else
            //{
            //    SocketListenerSSL.ConnectListener();
            //    // Đảm bảo ứng dụng không kết thúc ngay
            //    // test ký số

            //    Thread.Sleep(Timeout.Infinite);
            //}
            
        }
        public class TrayApplicationContext : ApplicationContext
        {
            private NotifyIcon trayIcon;
            private string appName = "TinDucSignApp";

            public TrayApplicationContext()
            {
                // Menu chuột phải
                ContextMenuStrip trayMenu = new ContextMenuStrip();
                trayMenu.Items.Add("Khởi động lại", null, RestartApp);
                trayMenu.Items.Add("Thoát", null, ExitApp);

                // NotifyIcon
                trayIcon = new NotifyIcon()
                {
                    Icon = new System.Drawing.Icon("logoCDK.ico", 40, 40),
                    ContextMenuStrip = trayMenu,
                    Text = "CDKSign",
                    Visible = true
                };

                // Đặt chạy khi khởi động Windows
                SetStartup(true);
            }

            private void SetStartup(bool enable)
            {
                string runKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
                using (RegistryKey registryKey = Registry.CurrentUser.OpenSubKey(runKey, true))
                {
                    if (enable)
                        registryKey.SetValue(appName, Application.ExecutablePath);
                    else
                        registryKey.DeleteValue(appName, false);
                }
            }

            private void ShowApp(object sender, EventArgs e)
            {
                // Ở đây mình demo bằng thông báo BalloonTip
                trayIcon.BalloonTipTitle = "Thông báo";
                trayIcon.BalloonTipText = "CDKSignServices";
                trayIcon.ShowBalloonTip(2000);
            }

            private void RestartApp(object sender, EventArgs e)
            {
                trayIcon.Visible = false;
                Application.Restart();
            }

            private void ExitApp(object sender, EventArgs e)
            {
                trayIcon.Visible = false;
                trayIcon.Dispose(); // giải phóng hoàn toàn icon tray

                Application.Exit(); // thoát message loop
                Environment.Exit(0); // đảm bảo kill process (nếu Application.Exit chưa đủ)
            }
        }
    }
}