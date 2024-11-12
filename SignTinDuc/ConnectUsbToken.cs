using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SignTinDuc
{
    public class ConnectUsbToken
    {

        /// <summary>
        /// Lấy thông tin thiết bị usbtoken
        /// </summary>
        /// <param name="pkcs11LibPath"></param>
        public static void GetUsbTokenInformation(string pkcs11LibPath)
        {
            // Khởi tạo thư viện PKCS#11
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
            using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pkcs11LibPath, AppType.SingleThreaded))
            {
                // Lấy danh sách các slot có token đang kết nối
                List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);

                if (slots.Count == 0)
                {
                    Console.WriteLine("Không tìm thấy thiết bị USB token nào.");
                    return;
                }

                // Duyệt qua từng slot để lấy thông tin token
                foreach (ISlot slot in slots)
                {
                    // Lấy thông tin của token trong slot hiện tại
                    ITokenInfo tokenInfo = slot.GetTokenInfo();

                    Console.WriteLine("Thông tin thiết bị USB token:");
                    Console.WriteLine($"- Tên token: {tokenInfo.Label}");
                    Console.WriteLine($"- Số serial: {tokenInfo.SerialNumber}");
                    Console.WriteLine($"- Hãng sản xuất: {tokenInfo.ManufacturerId}");
                    Console.WriteLine($"- Model: {tokenInfo.Model}");
                    //Console.WriteLine($"- Trạng thái token: {tokenInfo.Flags}");

                }
            }
        }
        private byte[] GetSignatureFromHashViaPkcs11(byte[] hash, string pin, string PKCS11LibPath)
        {
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
            using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, PKCS11LibPath, AppType.SingleThreaded))
            {
                ISlot slot = LoadSlot(pkcs11Library, "");
                using (ISession session = slot.OpenSession(SessionType.ReadOnly))
                {
                    session.Login(CKU.CKU_USER, pin);

                    //Search the private key based on the pulblic key CKA_ID
                    IObjectHandle keyHandle = null;
                    var searchTemplate = new List<IObjectAttribute>()
                    {
                        //CKO_PRIVATE_KEY in order to get handle for the private key
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                        //CKA_ID searching for the private key which matches the public key
                        //session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, CertificateToUse.PublicKeyCKAID.GetValueAsByteArray()),
                    };

                    //filter the search result. Since we search for a private key, only one is returned for each certificate
                    var search = session.FindAllObjects(searchTemplate);
                    keyHandle = search.FirstOrDefault();

                    if (keyHandle == null || (keyHandle.ObjectId == CK.CK_INVALID_HANDLE))
                    {
                        throw new Exception("Unable to read SmartCard KeyHandle. Make sure the correct PKCS11 Library is used");
                    }

                    try
                    {
                        //Create the signature (using the pin)
                        var pinAsByteArray = UTF8Encoding.UTF8.GetBytes(pin);
                        using (IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS))
                            return session.Sign(mechanism, keyHandle, pinAsByteArray, hash);
                    }
                    catch (Exception ex)
                    {
                        throw new Exception("Error creating the signature", ex);
                    }
                }
            }
        }
        public static ISlot LoadSlot(IPkcs11Library pkcs11Library, string tokenSerial)
        {
            // Lấy danh sách các slot có token đang cắm vào
            List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);

            // Kiểm tra từng slot để tìm slot có TokenSerial trùng khớp
            foreach (var slot in slots)
            {
                // Lấy thông tin token trong slot hiện tại
                ITokenInfo tokenInfo = slot.GetTokenInfo();

                // Kiểm tra TokenSerial với tokenSerial mà chúng ta đang tìm
                if (tokenInfo.SerialNumber == tokenSerial)
                {
                    return slot; // Trả về slot nếu tìm thấy
                }
            }

            // Nếu không tìm thấy slot phù hợp, ném ra ngoại lệ
            throw new Exception($"Không tìm thấy slot nào với TokenSerial: {tokenSerial}");
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        // Tải icon từ thư viện DLL
        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr LoadIcon(IntPtr hInstance, IntPtr lpIconName);

        public static Icon GetIconFromDll(string dllPath, int iconIndex = 0)
        {
            // Tải DLL vào bộ nhớ
            IntPtr hLibrary = LoadLibrary(dllPath);
            if (hLibrary == IntPtr.Zero)
            {
                throw new Exception("Không thể tải thư viện DLL.");
            }

            // Lấy icon từ DLL
            IntPtr hIcon = LoadIcon(hLibrary, new IntPtr(iconIndex));
            if (hIcon == IntPtr.Zero)
            {
                throw new Exception("Không tìm thấy biểu tượng trong DLL.");
            }

            return Icon.FromHandle(hIcon);
        }
    }
}
