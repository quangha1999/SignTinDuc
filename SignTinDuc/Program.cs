namespace SignTinDuc
{
    internal static class Program
    {
        /// <summary>
        ///  The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            // chỉ chạy socket ngầm
            // đầu tiên sẽ cần phải quét danh sách file cer
            // kiểm tra lấy thông tin các thiết bị
            bool showForm = false;
            if (showForm)
            {
                ApplicationConfiguration.Initialize();
                Application.Run(new LoginForm());
            }
            else
            {
                // danh sách dll kết nối chuẩn pkcs11 thiết bị usb token
                //List<string> test = ScanFolderLoadDll.FindPKCS11DLLs();
                // Lấy thông tin chứng thư số
                //var list =Certificate.GetListCert();
                //AsynchronousSocketListener.StartListening();
                //string PKCS11LibPath = @"E:\Code\PluginSign\nca_v6.dll";
                //string PKCS11LibPath = @"E:\Code\PluginSign\fpt-ca.dll";
                string[] path = new string[] { "nca_v6", "fpt-ca"};
                //SerialNumber = "0229581114280311" 54092101054304
                ConnectUsbToken.GetUsbTokenInformation(path, "54092101054304", (int)TypeSign.PDF);
            }
        }
    }
}