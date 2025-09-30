using iText.Bouncycastle.X509;
using iText.Commons.Bouncycastle.Cert;
using iText.Forms;
using iText.IO.Font;
using iText.Kernel.Colors;
using iText.Kernel.Font;
using iText.Kernel.Pdf;
using iText.Kernel.Pdf.Canvas;
using iText.Signatures;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Newtonsoft.Json;
using Org.BouncyCastle.X509;
using SignTinDuc.Utils;
using System;
using System.Collections.Concurrent;
using System.Data.SqlTypes;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using static iText.Signatures.PdfSigner;

namespace SignTinDuc
{
    public class ConnectUsbToken
    {
        private static readonly Dictionary<string, UsbTokenCacheItem> _cache = new();
        #region Kiểm tra lấy DLL tương ứng với thiết bị
        public static UsbTokenCacheItem CheckDLLMatchUSB(string arrData, string serial)
        {
            if (_cache.TryGetValue(serial, out var cachedItem))
            {
                return cachedItem;
            }

            UsbTokenCacheItem result = null;
            var lstDLL = ScanFolderLoadDll.FindPKCS11DLLs(arrData);

            if (lstDLL != null && lstDLL.Count > 0)
            {
                Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
                foreach (string pkcs11LibPath in lstDLL)
                {
                    using (IPkcs11Library pkcs11Library =
                           factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pkcs11LibPath, AppType.SingleThreaded))
                    {
                        List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
                        if (slots != null && slots.Count > 0)
                        {
                            foreach (ISlot slot in slots)
                            {
                                ITokenInfo tokenInfo = slot.GetTokenInfo();
                                if (tokenInfo != null && tokenInfo.SerialNumber == serial)
                                {
                                    result = new UsbTokenCacheItem
                                    {
                                        PathDll = pkcs11LibPath,
                                        Serial = tokenInfo.SerialNumber,
                                        Label = tokenInfo.Label,
                                        Icon = GetIconFromDll(pkcs11LibPath) // hàm custom để load icon DLL
                                    };

                                    _cache[serial] = result;
                                    break;
                                }
                            }
                        }
                    }

                    if (result != null)
                        break;
                }
            }
            return result;
        }
        // Xóa cache cho 1 serial (khi rút token)
        public static void Remove(string serial)
        {
            if (_cache.ContainsKey(serial))
                _cache.Remove(serial);
        }
        // Xóa toàn bộ cache
        public static void Clear()
        {
            _cache.Clear();
        }
        #endregion
        #region Kiểm tra đăng nhập thiết bị ký số
        public static Result GetUsbTokenInformation(string[] arrdata, string mess)
        {
            // arr1: Dll , arr2: serial thiết bị 
            Result msg = new Result();
            UsbTokenCacheItem usbtoken = CheckDLLMatchUSB(arrdata[1], arrdata[2]);
            if (usbtoken.PathDll == "")
            {
                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy thiết bị USB ký số\"}"), true, true, mess);
            }
            else
            {
                // Khởi tạo thư viện PKCS#11
                Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
                try
                {
                    using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, usbtoken.PathDll, AppType.SingleThreaded))
                    {
                        // Lấy danh sách các slot có token đang kết nối
                        List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
                        // Duyệt qua từng slot để lấy thông tin token
                        foreach (ISlot slot in slots)
                        {
                            // Lấy thông tin của token trong slot hiện tại
                            ITokenInfo tokenInfo = slot.GetTokenInfo();
                            // kiểm tra cơ chế mã hóa  fpt-ca :29 , nca_v6:51 theo chuẩn này CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS
                            //var mechanisms = slot.GetMechanismList();
                            // Mở session và đăng nhập vào token
                            string password = LoginForm.GetPassword(usbtoken.Icon, tokenInfo.Model);
                            if (password != null && password != "")
                            {
                                using (ISession session = slot.OpenSession(SessionType.ReadOnly))
                                {
                                    try
                                    {
                                        // Tìm kiếm và lấy chứng chỉ X.509 từ token
                                        session.Login(CKU.CKU_USER, password);
                                        // check login 
                                        var objectAttributes = new List<IObjectAttribute>
                                        {
                                            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),       // Đối tượng là chứng chỉ
                                            factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509)   // Chứng chỉ loại X.509
                                        };
                                        // Tìm kiếm tất cả các đối tượng khớp với thuộc tính
                                        List<IObjectHandle> certificates = session.FindAllObjects(objectAttributes);
                                        var certHandle = certificates[0];
                                        // Lấy khóa cá nhân từ token
                                        var keyAttributes = new List<IObjectAttribute>
                                        {
                                            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY)
                                        };
                                        List<IObjectHandle> privateKeyHandles = session.FindAllObjects(keyAttributes);
                                        if (privateKeyHandles.Count > 0)
                                        {
                                            var privateKeyHandle = privateKeyHandles[0];
                                            // Đọc nội dung file cần ký
                                            //byte[] data = File.ReadAllBytes(filePath);
                                            //byte[] hash = ComputeSha256Hash(data);
                                            //Lấy dữ liệu của chứng chỉ
                                            byte[] certificateData = session.GetAttributeValue(certHandle, new List<CKA> { CKA.CKA_VALUE })[0].GetValueAsByteArray();
                                            //Chuyển đổi dữ liệu thành đối tượng X509Certificate2
                                            var certificate = new X509Certificate2(certificateData);
                                            // chỉ lấy chứng thư số còn hạn sử dụng
                                            //if (certificate != null && certificate.NotBefore <= DateTime.Now && certificate.NotAfter >= DateTime.Now)
                                            //{
                                                var mechanism = factories.MechanismFactory.Create(CKM.CKM_SHA1_RSA_PKCS);
                                                // chữ ký
                                                //byte[] signature = session.Sign(mechanism, privateKeyHandle, hash);
                                                //SignPdfWithPkcs11(filePath, filePathSign, signature, certificate);
                                                //SignXmlDocument(fileXmlPath, fileSignXml, signature, certificate);
                                                session.Logout();
                                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Kết nối đến USB Token thành công.\"}"), true, true, mess);
                                            //}
                                            //else
                                            //{
                                            //    session.Logout();
                                            //    msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Chứng thư số đã hết hiệu lực.\"}"), true, true, mess);
                                            //}
                                        }
                                        else
                                        {
                                            session.Logout();
                                            msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy khóa cá nhân trên token\"}"), true, true, mess);
                                        }
                                    }
                                    catch (Exception e)
                                    {
                                        msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn nhập sai mã PIN\"}"), true, true, mess);
                                    }
                                }
                            }
                            else
                            {
                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn chưa nhập mã PIN\"}"), true, true, mess);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không kết nối được USB ký số\"}"), true, true, mess);
                }
            }
            return msg;
        }
        #endregion
        #region Hàm tính toán SHA-256 hash dữ liệu
        private static byte[] ComputeSha256Hash(byte[] data)
        {
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                return sha256.ComputeHash(data);
            }
        }
        #endregion
        #region Lấy icon từ DLL
        public static Icon GetIconFromDll(string dllPath, int iconIndex = 0)
        {
            Icon icon = Icon.ExtractAssociatedIcon(dllPath);
            return icon;

        }
        #endregion
        #region Ký byte pdf
        public static string SignPdfWithPkcs11(byte[] pdfData, byte[] signature, X509Certificate2 certificate, string jsonToaDo, ISession session, IObjectHandle privateKeyHandle)
        {
            List<SignaturePosition> toaDoList = new List<SignaturePosition>() {
            new SignaturePosition{x= 361, y= 817,width= 220,height= 20,page= 1,text= "Sao ý bản chính",fontName= "Time",fontStyle= 0,fontSize= 10,fontColor= "000" } };
            byte[] currentPdf = pdfData;

            foreach (var toaDo in toaDoList)
            {
                using (MemoryStream inputStream = new MemoryStream(currentPdf))
                using (PdfReader reader = new PdfReader(inputStream))
                using (MemoryStream outputStream = new MemoryStream())
                {
                    PdfSigner signer = new PdfSigner(reader, outputStream, new StampingProperties().UseAppendMode());

                    var rect = new iText.Kernel.Geom.Rectangle((int)toaDo.x, (int)toaDo.y, (int)toaDo.width, (int)toaDo.height);
                    //IExternalSignature pks = new ExternalBlankSignature(signature, "RSA", "SHA-256");
                    IExternalSignature pks = new Pkcs11Signature(session, privateKeyHandle, "SHA-256");
                    IExternalDigest digest = new BouncyCastleDigest();

                    Org.BouncyCastle.X509.X509Certificate bouncyCert = ConvertToBouncyCastleCertificate(certificate);
                    IX509Certificate iTextCert = new X509CertificateBC(bouncyCert);
                    IX509Certificate[] certChain = new IX509Certificate[] { iTextCert };

                    string fontPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "TIMES.ttf");
                    PdfFont font = PdfFontFactory.CreateFont(fontPath, PdfEncodings.IDENTITY_H);
                    ITSAClient tsaClient = new TSAClientBouncyCastle("http://tsa.ca.gov.vn");

                    signer.SignDetached(digest, pks, certChain, null, null, tsaClient, 0, PdfSigner.CryptoStandard.CADES);
                    PdfSignatureAppearance appearance = signer.GetSignatureAppearance()
                        .SetPageNumber(toaDo.page)
                        .SetPageRect(rect)
                        .SetLayer2Text(toaDo.text ?? "")
                        .SetLayer2Font(font)
                        .SetLayer2FontSize(toaDo.fontSize)
                        .SetReuseAppearance(false)
                        .SetReason("Ký số văn thư")
                        .SetLocation("Việt Nam");

                    // Duy nhất lần đầu mới đặt cấp độ chứng thực
                    if (toaDo == toaDoList[0])
                        signer.SetCertificationLevel(PdfSigner.CERTIFIED_FORM_FILLING_AND_ANNOTATIONS);
                    else
                        signer.SetCertificationLevel(PdfSigner.NOT_CERTIFIED);

                  

                    // Cập nhật PDF hiện tại để lặp ký tiếp
                    currentPdf = outputStream.ToArray();
                }
            }

            return Convert.ToBase64String(currentPdf);
        }
        public static Result SignMultiPdfWithPkcs11(List<MultipleData> multipleDatas, byte[] signature, X509Certificate2 certificate)
        {

            // Đọc file PDF gốc với PdfReader
            foreach (var bytedata in multipleDatas)
            {
                using (MemoryStream inputStream = new MemoryStream(bytedata.bytes))
                using (PdfReader pdfReader = new PdfReader(inputStream))
                using (MemoryStream outputStream = new MemoryStream())
                {
                    // Tạo đối tượng PdfSigner để xử lý ký số
                    PdfSigner pdfSigner = new PdfSigner(pdfReader, outputStream, new StampingProperties());
                    IExternalSignature pks = new ExternalBlankSignature(signature, "RSA", "SHA-256");
                    IExternalDigest digest = new BouncyCastleDigest();

                    Org.BouncyCastle.X509.X509Certificate bouncyCert = ConvertToBouncyCastleCertificate(certificate);

                    // Chuyển đổi thành iText IX509Certificate
                    IX509Certificate iTextCert = new X509CertificateBC(bouncyCert);
                    float x = 595 - 150; // Vị trí X, 595 là chiều rộng của A4, 150 là chiều rộng chữ ký
                    float y = 842 - 50;  // Vị trí Y, 842 là chiều cao của A4, 50 là chiều cao chữ ký
                    float width = 150;   // Chiều rộng chữ ký
                    float height = 50;   // Chiều cao chữ ký
                    string fontPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "TIMES.ttf");
                    //string fontPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "TIMES.ttf");
                    PdfFont font = PdfFontFactory.CreateFont(fontPath, PdfEncodings.IDENTITY_H);

                    IX509Certificate[] certChain = new IX509Certificate[] { iTextCert };
                    PdfSignatureAppearance signatureAppearance = pdfSigner.GetSignatureAppearance()
                                                                       .SetPageRect(new iText.Kernel.Geom.Rectangle(x, y, width, height))
                                                                       .SetReason("Digital signature")
                                                                       .SetLocation("Location")
                                                                       .SetLayer2Font(font)
                                                                       ;
                    pdfSigner.SetCertificationLevel(PdfSigner.CERTIFIED_NO_CHANGES_ALLOWED);
                    //ITSAClient tsaClient = new TSAClientBouncyCastle("http://tsa.ca.gov.vn");
                    // Ký số file PDF
                    //pdfSigner.SignDetached(digest, pks, certChain, null, null, tsaClient, 0, PdfSigner.CryptoStandard.CADES);
                    pdfSigner.SignDetached(digest, pks, certChain, null, null, null, 0, PdfSigner.CryptoStandard.CADES);
                }
            }

            return null;
        }
        #endregion
        #region Ký byte xml
        public static string SignXmlDocument(byte[] xmlBytes, byte[] signature, X509Certificate2 certificate, string imageBase64, int x, int y, int width, int height)
        {
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(Encoding.UTF8.GetString(xmlBytes));

            XmlElement signatureElement = xmlDoc.CreateElement("Signature", "http://www.w3.org/2000/09/xmldsig#");

            XmlElement signedInfoElement = xmlDoc.CreateElement("SignedInfo", "http://www.w3.org/2000/09/xmldsig#");
            signatureElement.AppendChild(signedInfoElement);

            XmlElement canonicalizationMethod = xmlDoc.CreateElement("CanonicalizationMethod", "http://www.w3.org/2000/09/xmldsig#");
            canonicalizationMethod.SetAttribute("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
            signedInfoElement.AppendChild(canonicalizationMethod);

            XmlElement signatureMethod = xmlDoc.CreateElement("SignatureMethod", "http://www.w3.org/2000/09/xmldsig#");
            signatureMethod.SetAttribute("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            signedInfoElement.AppendChild(signatureMethod);

            XmlElement reference = xmlDoc.CreateElement("Reference", "http://www.w3.org/2000/09/xmldsig#");
            reference.SetAttribute("URI", "");
            signedInfoElement.AppendChild(reference);

            XmlElement digestMethod = xmlDoc.CreateElement("DigestMethod", "http://www.w3.org/2000/09/xmldsig#");
            digestMethod.SetAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
            reference.AppendChild(digestMethod);

            XmlElement digestValue = xmlDoc.CreateElement("DigestValue", "http://www.w3.org/2000/09/xmldsig#");
            digestValue.InnerText = Convert.ToBase64String(new byte[32]);
            reference.AppendChild(digestValue);

            XmlElement signatureValueElement = xmlDoc.CreateElement("SignatureValue", "http://www.w3.org/2000/09/xmldsig#");
            signatureValueElement.InnerText = Convert.ToBase64String(signature);
            signatureElement.AppendChild(signatureValueElement);

            XmlElement keyInfoElement = xmlDoc.CreateElement("KeyInfo", "http://www.w3.org/2000/09/xmldsig#");
            signatureElement.AppendChild(keyInfoElement);

            XmlElement x509Data = xmlDoc.CreateElement("X509Data", "http://www.w3.org/2000/09/xmldsig#");
            keyInfoElement.AppendChild(x509Data);
            // subject name
            XmlElement x509SubjectNameElement = xmlDoc.CreateElement("X509SubjectName", "http://www.w3.org/2000/09/xmldsig#");
            x509SubjectNameElement.InnerText = certificate.Subject;
            x509Data.AppendChild(x509SubjectNameElement);
            // certificate
            XmlElement x509CertificateElement = xmlDoc.CreateElement("X509Certificate", "http://www.w3.org/2000/09/xmldsig#");
            x509CertificateElement.InnerText = Convert.ToBase64String(certificate.Export(X509ContentType.Cert));
            x509Data.AppendChild(x509CertificateElement);

            // Add SignatureProperties for signing time
            XmlElement objectElement = xmlDoc.CreateElement("Object", "http://www.w3.org/2000/09/xmldsig#");
            XmlElement signatureProperties = xmlDoc.CreateElement("SignatureProperties", "http://www.w3.org/2000/09/xmldsig#");
            objectElement.AppendChild(signatureProperties);

            XmlElement signatureProperty = xmlDoc.CreateElement("SignatureProperty", "http://www.w3.org/2000/09/xmldsig#");
            signatureProperty.SetAttribute("Id", "SigningTime");
            signatureProperty.SetAttribute("Target", "#");
            signatureProperties.AppendChild(signatureProperty);

            TimeZoneInfo vnZone = TimeZoneInfo.FindSystemTimeZoneById("SE Asia Standard Time");
            DateTime vnTime = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, vnZone);

            XmlElement signingTime = xmlDoc.CreateElement("SigningTime", "http://example.org/#signatureProperties");
            signingTime.InnerText = vnTime.ToString("yyyy-MM-ddTHH:mm:ssK", CultureInfo.InvariantCulture);
            signatureProperty.AppendChild(signingTime);

            // Add Base64 Image and Coordinates
            XmlElement signatureImage = xmlDoc.CreateElement("SignatureImage", "http://www.w3.org/2000/09/xmldsig#");
            signatureImage.InnerText = imageBase64;
            objectElement.AppendChild(signatureImage);

            signatureElement.AppendChild(objectElement);

            xmlDoc.DocumentElement.AppendChild(signatureElement);

            return xmlDoc.OuterXml;
        }
      
        public static void SignMultiXmlDocument(string xmlFilePath, string signedXmlFilePath, byte[] signature, X509Certificate2 certificate)
        {
            // Tạo đối tượng XmlDocument từ file XML gốc
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load(xmlFilePath);

            XmlElement signatureElement = xmlDoc.CreateElement("Signature", "http://www.w3.org/2000/09/xmldsig#");

            XmlElement signedInfoElement = xmlDoc.CreateElement("SignedInfo", "http://www.w3.org/2000/09/xmldsig#");
            signatureElement.AppendChild(signedInfoElement);

            XmlElement canonicalizationMethod = xmlDoc.CreateElement("CanonicalizationMethod", "http://www.w3.org/2000/09/xmldsig#");
            canonicalizationMethod.SetAttribute("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
            signedInfoElement.AppendChild(canonicalizationMethod);

            XmlElement signatureMethod = xmlDoc.CreateElement("SignatureMethod", "http://www.w3.org/2000/09/xmldsig#");
            signatureMethod.SetAttribute("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            signedInfoElement.AppendChild(signatureMethod);

            XmlElement reference = xmlDoc.CreateElement("Reference", "http://www.w3.org/2000/09/xmldsig#");
            reference.SetAttribute("URI", "");
            signedInfoElement.AppendChild(reference);

            XmlElement digestMethod = xmlDoc.CreateElement("DigestMethod", "http://www.w3.org/2000/09/xmldsig#");
            digestMethod.SetAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
            reference.AppendChild(digestMethod);

            XmlElement digestValue = xmlDoc.CreateElement("DigestValue", "http://www.w3.org/2000/09/xmldsig#");
            digestValue.InnerText = Convert.ToBase64String(new byte[32]);  // Placeholder value
            reference.AppendChild(digestValue);

            XmlElement signatureValueElement = xmlDoc.CreateElement("SignatureValue", "http://www.w3.org/2000/09/xmldsig#");
            signatureValueElement.InnerText = Convert.ToBase64String(signature);
            signatureElement.AppendChild(signatureValueElement);

            XmlElement keyInfoElement = xmlDoc.CreateElement("KeyInfo", "http://www.w3.org/2000/09/xmldsig#");
            signatureElement.AppendChild(keyInfoElement);

            XmlElement x509Data = xmlDoc.CreateElement("X509Data", "http://www.w3.org/2000/09/xmldsig#");
            keyInfoElement.AppendChild(x509Data);

            XmlElement x509CertificateElement = xmlDoc.CreateElement("X509Certificate", "http://www.w3.org/2000/09/xmldsig#");
            x509CertificateElement.InnerText = Convert.ToBase64String(certificate.Export(X509ContentType.Cert));
            x509Data.AppendChild(x509CertificateElement);

            xmlDoc.DocumentElement.AppendChild(signatureElement);

            xmlDoc.Save(signedXmlFilePath);
        }
        #endregion
        #region Chuyển đổi X509Certificate2 của .NET thành BouncyCastle X509Certificate
        public static Org.BouncyCastle.X509.X509Certificate ConvertToBouncyCastleCertificate(X509Certificate2 cert)
        {
            var certParser = new X509CertificateParser();
            return certParser.ReadCertificate(cert.RawData);
        }
        #endregion
        #region Lấy thông tin usb đang kết nối
        public static Result GetInformationDevices(string dll, string data, string messId)
        {
            Result msg = new Result();
            var lstDLL = ScanFolderLoadDll.FindPKCS11DLLs(dll);
            // dll hoạt động bình thường
            string SerialDevices = "";
            string pathDLL = "";
            // Khởi tạo thư viện PKCS#11
            if (lstDLL != null && lstDLL.Count > 0)
            {
                Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
                foreach (string pkcs11LibPath in lstDLL)
                {
                    using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pkcs11LibPath, AppType.SingleThreaded))
                    {
                        List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
                        if (slots != null && slots.Count > 0)
                        {
                            // thông tin thiết bị
                            foreach (ISlot slot in slots)
                            {
                                ITokenInfo tokenInfo = slot.GetTokenInfo();
                                if (tokenInfo != null && tokenInfo.Label.ToLower().Contains(data.ToLower()))
                                {
                                    SerialDevices = tokenInfo.SerialNumber;
                                    pathDLL = pkcs11LibPath; break;
                                }
                            }
                        }

                    }
                }
            }
            if (pathDLL == "")
            {
                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy thiết bị USB ký số tương ứng với nhà cung cấp chữ ký đang chọn\"}"), true, true, messId);
            }
            else
            {
                Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
                try
                {
                    using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pathDLL, AppType.SingleThreaded))
                    {
                        // Lấy danh sách các slot có token đang kết nối
                        List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
                        // Duyệt qua từng slot để lấy thông tin token
                        foreach (ISlot slot in slots)
                        {
                            // Lấy thông tin của token trong slot hiện tại
                            ITokenInfo tokenInfo = slot.GetTokenInfo();
                            // lấy thông tin liên quan đến usb token số serial-token

                            var icon = GetIconFromDll(pathDLL, 0);
                            // Mở session và đăng nhập vào token
                            string password = LoginForm.GetPassword(icon, tokenInfo.Model);
                            if (password != null && password != "")
                            {
                                using (ISession session = slot.OpenSession(SessionType.ReadOnly))
                                {
                                    try
                                    {
                                        // Tìm kiếm và lấy chứng chỉ X.509 từ token
                                        session.Login(CKU.CKU_USER, password);
                                        // check login 
                                        var objectAttributes = new List<IObjectAttribute>
                                        {
                                            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),       // Đối tượng là chứng chỉ
                                            factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509)   // Chứng chỉ loại X.509
                                        };
                                        // Tìm kiếm tất cả các đối tượng khớp với thuộc tính
                                        List<IObjectHandle> certificates = session.FindAllObjects(objectAttributes);
                                        var certHandle = certificates[0];
                                        // Lấy khóa cá nhân từ token
                                        var keyAttributes = new List<IObjectAttribute>
                                        {
                                            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY)
                                        };
                                        List<IObjectHandle> privateKeyHandles = session.FindAllObjects(keyAttributes);
                                        if (privateKeyHandles.Count > 0)
                                        {
                                            var privateKeyHandle = privateKeyHandles[0];
                                            byte[] certificateData = session.GetAttributeValue(certHandle, new List<CKA> { CKA.CKA_VALUE })[0].GetValueAsByteArray();
                                            //Chuyển đổi dữ liệu thành đối tượng X509Certificate2
                                            var certificate = new X509Certificate2(certificateData);
                                            // chỉ lấy chứng thư số còn hạn sử dụng
                                            //if (certificate != null && certificate.NotBefore <= DateTime.Now && certificate.NotAfter >= DateTime.Now)
                                            //{
                                            var mechanism = factories.MechanismFactory.Create(CKM.CKM_SHA1_RSA_PKCS);
                                            session.Logout();
                                            var nic = NetworkInterface.GetAllNetworkInterfaces()
                                                        .FirstOrDefault(n =>
                                                            n.OperationalStatus == OperationalStatus.Up &&
                                                            n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                                                            n.GetPhysicalAddress().GetAddressBytes().Length == 6);

                                            string mac = nic?.GetPhysicalAddress().ToString();

                                            string ip = nic?.GetIPProperties().UnicastAddresses
                                                .FirstOrDefault(ipinfo => ipinfo.Address.AddressFamily == AddressFamily.InterNetwork)
                                                ?.Address.ToString();
                                            var objData = new
                                            {
                                                SerialDevice = SerialDevices,
                                                SerialCertificate = certificate.SerialNumber,
                                                UserToken = certificate.GetNameInfo(X509NameType.SimpleName, false),
                                                MacAdress= mac,
                                                IpAdress= ip,
                                                Message = "Kết nối đến USB token thành công."
                                            };
                                            string jsonData = JsonConvert.SerializeObject(objData);
                                            msg = new Result((int)ResultStatus.OK, JsonConvert.DeserializeObject(jsonData), true, true, messId);
                                            //}
                                            //else
                                            //{
                                            //   session.Logout();
                                            //   msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Chứng thư số đã hết hiệu lực.\"}"), true, true, messId);
                                            //}
                                        }
                                        else
                                        {
                                            session.Logout();
                                            msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy khóa cá nhân trên token\"}"), true, true, messId);
                                        }
                                    }
                                    catch (Exception e)
                                    {
                                        msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn nhập sai mã PIN\"}"), true, true, messId);
                                    }
                                }
                            }
                            else
                            {
                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn chưa nhập mã PIN\"}"), true, true, messId);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không kết nối được USB ký số\"}"), true, true, messId);
                }
            }
            //return pathDLL;
            return msg;
        }
        #endregion
        #region Connect and sign pdf dùng dữ liệu dll từ TempStorage
        public static Result SignPdfUsbToken(string dll, string serial, string dataBase64, string dataImageBase64, string messId,string jsontoado)
        {
            // arr1: Dll , arr2: serial thiết bị , arr3: base64 pdf
            Result msg = new Result();
            // lấy lại dll từ biển TempStorage
            UsbTokenCacheItem usbtoken = CheckDLLMatchUSB(dll, serial);
            if (usbtoken.PathDll == "")
            {
                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy thiết bị USB ký số\"}"), true, true, messId);
            }
            else
            {
                // Khởi tạo thư viện PKCS#11
                Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
                try
                {
                    using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, usbtoken.PathDll, AppType.SingleThreaded))
                    {
                        // Lấy danh sách các slot có token đang kết nối
                        List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
                        // Duyệt qua từng slot để lấy thông tin token
                        foreach (ISlot slot in slots)
                        {
                            // Lấy thông tin của token trong slot hiện tại
                            ITokenInfo tokenInfo = slot.GetTokenInfo();
                            // kiểm tra cơ chế mã hóa  fpt-ca :29 , nca_v6:51 theo chuẩn này CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS
                            //var mechanisms = slot.GetMechanismList();
                            var icon = GetIconFromDll(usbtoken.PathDll, 0);
                            string password = usbtoken.Password;

                            if (string.IsNullOrEmpty(password))
                            {
                                // hỏi user nhập lần đầu
                                password = LoginForm.GetPassword(usbtoken.Icon, tokenInfo.Model);

                            }
                            // Mở session và đăng nhập vào token
                            //string password = LoginForm.GetPassword(icon, tokenInfo.Model);

                            if (password != null && password != "")
                            {
                                SetPassword(serial, password);
                                using (ISession session = slot.OpenSession(SessionType.ReadOnly))
                                {
                                    try
                                    {
                                        // Tìm kiếm và lấy chứng chỉ X.509 từ token
                                        session.Login(CKU.CKU_USER, password);
                                        // check login 
                                        var objectAttributes = new List<IObjectAttribute>
                                        {
                                            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),       // Đối tượng là chứng chỉ
                                            factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509)   // Chứng chỉ loại X.509
                                        };
                                        // Tìm kiếm tất cả các đối tượng khớp với thuộc tính
                                        List<IObjectHandle> certificates = session.FindAllObjects(objectAttributes);
                                        var certHandle = certificates[0];
                                        // Lấy khóa cá nhân từ token
                                        var keyAttributes = new List<IObjectAttribute>
                                        {
                                            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY)
                                        };
                                        List<IObjectHandle> privateKeyHandles = session.FindAllObjects(keyAttributes);
                                        if (privateKeyHandles.Count > 0)
                                        {
                                            var privateKeyHandle = privateKeyHandles[0];

                                            // Dữ liệu cần ký (Base64 → byte[])
                                            byte[] data = Convert.FromBase64String(dataBase64);

                                            // Lấy dữ liệu chứng chỉ từ token
                                            byte[] certificateData = session.GetAttributeValue(certHandle, new List<CKA> { CKA.CKA_VALUE })[0].GetValueAsByteArray();
                                            var certificate = new X509Certificate2(certificateData);

                                            // Kiểm tra thời hạn chứng thư (nếu cần)
                                            //if (certificate.NotBefore <= DateTime.Now && certificate.NotAfter >= DateTime.Now)
                                            //{
                                                // Cơ chế ký: Token sẽ tự hash bằng SHA256 và ký
                                                var mechanism = factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS);

                                                // Thực hiện ký dữ liệu gốc (không hash trước)
                                                byte[] signature = session.Sign(mechanism, privateKeyHandle, data);

                                                // Ký PDF bằng chữ ký vừa tạo + chứng chỉ
                                                string base64data = SignPdfWithPkcs11(data, signature, certificate, jsontoado, session, privateKeyHandle);

                                                msg = new Result((int)ResultStatus.OK, base64data, true, true, messId);
                                            //}
                                            //else
                                            //{
                                            //    msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Chứng thư số đã hết hiệu lực.\"}"), true, true, messId);
                                            //}

                                            session.Logout();
                                        }
                                        else
                                        {
                                            session.Logout();
                                            msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy khóa cá nhân trên token \"}"), true, true, messId);
                                        }
                                    }
                                    catch (Exception e)
                                    {
                                        msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn nhập sai mã PIN\"}"), true, true, messId);
                                    }
                                }
                            }
                            else
                            {
                                SetPassword(serial, null);
                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn chưa nhập mã PIN\"}"), true, true, messId);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không kết nối được USB ký số\"}"), true, true, messId);
                }
            }
            return msg;
        }
        #endregion
        #region Connect sign xml dùng dữ liệu
        public static Result SignXmlUsbToken(string dll, string serial, string dataBase64,string dataImageBase64, string messId)
        {
            // arr1: Dll , arr2: serial thiết bị , arr3: base64 xml,
            Result msg = new Result();
            // lấy từ cache
            UsbTokenCacheItem usbtoken = CheckDLLMatchUSB(dll, serial);
            if (usbtoken.PathDll == "")
            {
                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy thiết bị USB ký số\"}"), true, true, messId);
            }
            else
            {
                // Khởi tạo thư viện PKCS#11
                Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
                try
                {
                    using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, usbtoken.PathDll, AppType.SingleThreaded))
                    {
                        // Lấy danh sách các slot có token đang kết nối
                        List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
                        // Duyệt qua từng slot để lấy thông tin token
                        foreach (ISlot slot in slots)
                        {
                            // Lấy thông tin của token trong slot hiện tại
                            ITokenInfo tokenInfo = slot.GetTokenInfo();
                            // kiểm tra cơ chế mã hóa  fpt-ca :29 , nca_v6:51 theo chuẩn này CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS
                            //var mechanisms = slot.GetMechanismList();
                            // Mở session và đăng nhập vào token
                            string password = usbtoken.Password;

                            if (string.IsNullOrEmpty(password))
                            {
                                // hỏi user nhập lần đầu
                                password = LoginForm.GetPassword(usbtoken.Icon, tokenInfo.Model);

                            }
                            // Mở session và đăng nhập vào token
                            //string password = LoginForm.GetPassword(icon, tokenInfo.Model);

                            if (password != null && password != "")
                            {
                                
                                using (ISession session = slot.OpenSession(SessionType.ReadOnly))
                                {
                                    try
                                    {
                                        // Tìm kiếm và lấy chứng chỉ X.509 từ token
                                        session.Login(CKU.CKU_USER, password);
                                        SetPassword(serial, password);
                                        // check login 
                                        var objectAttributes = new List<IObjectAttribute>
                                        {
                                            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),       // Đối tượng là chứng chỉ
                                            factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509)   // Chứng chỉ loại X.509
                                        };
                                        // Tìm kiếm tất cả các đối tượng khớp với thuộc tính
                                        List<IObjectHandle> certificates = session.FindAllObjects(objectAttributes);
                                        var certHandle = certificates[0];
                                        // Lấy khóa cá nhân từ token
                                        var keyAttributes = new List<IObjectAttribute>
                                        {
                                            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY)
                                        };
                                        List<IObjectHandle> privateKeyHandles = session.FindAllObjects(keyAttributes);
                                        if (privateKeyHandles.Count > 0)
                                        {
                                            var privateKeyHandle = privateKeyHandles[0];

                                            // Dữ liệu cần ký (Base64 → byte[])
                                            byte[] data = Convert.FromBase64String(dataBase64);

                                            // Lấy dữ liệu chứng chỉ từ token
                                            byte[] certificateData = session.GetAttributeValue(certHandle, new List<CKA> { CKA.CKA_VALUE })[0].GetValueAsByteArray();
                                            var certificate = new X509Certificate2(certificateData);

                                            // Kiểm tra thời hạn chứng thư (nếu cần)
                                            //if (certificate.NotBefore <= DateTime.Now && certificate.NotAfter >= DateTime.Now)
                                            //{
                                            // Cơ chế ký: Token sẽ tự hash bằng SHA256 và ký
                                            var mechanism = factories.MechanismFactory.Create(CKM.CKM_SHA1_RSA_PKCS);

                                            // Thực hiện ký dữ liệu gốc (không hash trước)
                                            byte[] signature = session.Sign(mechanism, privateKeyHandle, data);
                                            //SignPdfWithPkcs11(filePath, filePathSign, signature, certificate);
                                            string base64data = SignXmlDocument(data, signature, certificate, dataImageBase64, 1, 50, 50, 50);
                                            // Lấy danh sách cơ chế hỗ trợ
                                           
                                            //string base64data = SignXmlDocument(dataBase64, session, privateKeyHandle, certificate, dataImageBase64,1,1,1,1);

                                            msg = new Result((int)ResultStatus.OK, base64data, true, true, messId);
                                            session.Logout();
                                            //}
                                            //else
                                            //{
                                            //  session.Logout();
                                            //  msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Chứng thư số đã hết hiệu lực.\"}"), true, true, messId);
                                            //}
                                        }
                                        else
                                        {
                                            SetPassword(serial, null);
                                            session.Logout();
                                            msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy khóa cá nhân trên token \"}"), true, true, messId);
                                        }
                                    }
                                    catch (Exception e)
                                    {
                                        SetPassword(serial, null);
                                        msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn nhập sai mã PIN\"}"), true, true, messId);
                                    }
                                }
                            }
                            else
                            {
                                SetPassword(serial, null);
                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn chưa nhập mã PIN\"}"), true, true, messId);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn chưa nhập mã PIN\"}"), true, true, messId);
                }
            }
            return msg;
        }

        public static Result SignXmlUsbToken_V1(string dll, string serial, string dataBase64, string dataImageBase64, string messId)
        {
            Result msg = new Result();

            try
            {
                // Bước 1: Check chứng thư trong Windows Certificate Store trước
                X509Certificate2 certificate = null;
                X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly);

                foreach (var cert in store.Certificates)
                {
                    if (cert.SerialNumber.Equals(serial, StringComparison.OrdinalIgnoreCase) 
                        //&& cert.NotBefore <= DateTime.Now && cert.NotAfter >= DateTime.Now
                        )
                    {
                        certificate = cert;
                        break;
                    }
                }

                store.Close();

                if (certificate == null)
                {
                    msg = new Result((int)ResultStatus.ERROR,
                        JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy chứng thư số hợp lệ trong Windows Store\"}"),
                        true, true, messId);
                    return msg;
                }

                // Bước 2: Dùng RSACryptoServiceProvider/RSACng để ký (Windows sẽ gọi vào Token CSP/KSP bên dưới)
                byte[] data = Convert.FromBase64String(dataBase64);

                byte[] signature;
                using (var rsa = certificate.GetRSAPrivateKey())
                {
                    if (rsa == null)
                    {
                        msg = new Result((int)ResultStatus.ERROR,
                            JsonConvert.DeserializeObject("{\"Message\":\"Không lấy được private key từ token\"}"),
                            true, true, messId);
                        return msg;
                    }

                    // Ký SHA256
                    signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }

                // Bước 3: Gắn chữ ký vào XML (hàm bạn đã có sẵn)
                string base64data = SignXmlDocument(data, signature, certificate, dataImageBase64, 1, 50, 50, 50);

                msg = new Result((int)ResultStatus.OK, base64data, true, true, messId);
            }
            catch (CryptographicException ex)
            {
                msg = new Result((int)ResultStatus.ERROR,
                    JsonConvert.DeserializeObject("{\"Message\":\"Bạn nhập sai mã PIN hoặc chưa cắm USB Token\"}"),
                    true, true, messId);
            }
            catch (Exception ex)
            {
                msg = new Result((int)ResultStatus.ERROR,
                    JsonConvert.DeserializeObject("{\"Message\":\"Có lỗi khi ký: " + ex.Message + "\"}"),
                    true, true, messId);
            }

            return msg;
        }


        #endregion
        #region Ký nhiều file xml 
        public static Result SignMultipleFileXML(string dll, string serial, string dataBase64, string dataImageBase64, string messId)
        {
            Result msg = new Result();
            // lấy lại dll từ biển TempStorage
            UsbTokenCacheItem tokenusb = CheckDLLMatchUSB(dll, serial);
            if (tokenusb.PathDll == "")
            {
                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy thiết bị USB ký số\"}"), true, true, messId);

            }
            else
            {
                Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
                try
                {
                    using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, tokenusb.PathDll, AppType.SingleThreaded))
                    {
                        // Lấy danh sách các slot có token đang kết nối
                        List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
                        // Duyệt qua từng slot để lấy thông tin token
                        foreach (ISlot slot in slots)
                        {
                            // Lấy thông tin của token trong slot hiện tại
                            ITokenInfo tokenInfo = slot.GetTokenInfo();
                            // kiểm tra cơ chế mã hóa  fpt-ca :29 , nca_v6:51 theo chuẩn này CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS
                            //var mechanisms = slot.GetMechanismList();
                            var icon = GetIconFromDll(tokenusb.PathDll, 0);
                            // Mở session và đăng nhập vào token
                            string password = LoginForm.GetPassword(icon, tokenInfo.Model);
                            if (password != null && password != "")
                            {
                                using (ISession session = slot.OpenSession(SessionType.ReadOnly))
                                {
                                    try
                                    {
                                        // Tìm kiếm và lấy chứng chỉ X.509 từ token
                                        session.Login(CKU.CKU_USER, password);
                                        // check login 
                                        var objectAttributes = new List<IObjectAttribute>
                                        {
                                            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),       // Đối tượng là chứng chỉ
                                            factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509)   // Chứng chỉ loại X.509
                                        };
                                        // Tìm kiếm tất cả các đối tượng khớp với thuộc tính
                                        List<IObjectHandle> certificates = session.FindAllObjects(objectAttributes);
                                        var certHandle = certificates[0];
                                        // Lấy khóa cá nhân từ token
                                        var keyAttributes = new List<IObjectAttribute>
                                        {
                                            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY)
                                        };
                                        List<IObjectHandle> privateKeyHandles = session.FindAllObjects(keyAttributes);
                                        if (privateKeyHandles.Count > 0)
                                        {
                                            var privateKeyHandle = privateKeyHandles[0];
                                            // Đọc nội dung file cần ký
                                            // Danh sách file nên tiến hành đọc lần lượt từ file ký
                                            // giải mã base64
                                            List<Data> list = new List<Data>();
                                            byte[] data = Convert.FromBase64String(dataBase64);
                                            byte[] hash = ComputeSha256Hash(data);
                                            //Lấy dữ liệu của chứng chỉ
                                            byte[] certificateData = session.GetAttributeValue(certHandle, new List<CKA> { CKA.CKA_VALUE })[0].GetValueAsByteArray();
                                            //Chuyển đổi dữ liệu thành đối tượng X509Certificate2
                                            var certificate = new X509Certificate2(certificateData);
                                            // chỉ lấy chứng thư số còn hạn sử dụng
                                            //if (certificate != null && certificate.NotBefore <= DateTime.Now && certificate.NotAfter >= DateTime.Now)
                                            //{
                                            var mechanism = factories.MechanismFactory.Create(CKM.CKM_SHA1_RSA_PKCS);
                                            // chữ ký
                                            byte[] signature = session.Sign(mechanism, privateKeyHandle, hash);
                                            //SignPdfWithPkcs11(filePath, filePathSign, signature, certificate);
                                          
                                            // chữ ký số
                                            string base64data = SignXmlDocument(data, signature, certificate, dataImageBase64, 1, 50, 50, 50);

                                            msg = new Result((int)ResultStatus.OK, base64data, true, true, messId);
                                            session.Logout();
                                            // }
                                            //else
                                            //{
                                            // session.Logout();
                                            //  msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Chứng thư số đã hết hiệu lực.\"}"), true, true);
                                            //}
                                        }
                                        else
                                        {
                                            session.Logout();
                                            msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy khóa cá nhân trên token \"}"), true, true, messId);
                                        }
                                    }
                                    catch (Exception e)
                                    {
                                        msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn nhập sai mã PIN\"}"), true, true, messId);
                                    }
                                }
                            }
                            else
                            {
                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn chưa nhập mã PIN\"}"), true, true, messId);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn chưa nhập mã PIN\"}"), true, true, messId);
                }
            }
            return msg;
        }
        #endregion

        public static void SetPassword(string serial, string password)
        {
            if (_cache.TryGetValue(serial, out var cachedItem))
                cachedItem.Password = password;
        }
        public class Data
        {
            public string? Id { get; set; }
            public string? SignXml { get; set; }
        }
        public class UsbTokenCacheItem
        {
            public string PathDll { get; set; }
            public string Serial { get; set; }
            public string Label { get; set; }
            public Icon Icon { get; set; }
            public string Password { get; set; }
        }
    }
}
