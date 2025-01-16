using iText.Bouncycastle.X509;
using iText.Commons.Bouncycastle.Cert;
using iText.Forms;
using iText.IO.Font;
using iText.Kernel.Font;
using iText.Kernel.Pdf;
using iText.Signatures;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Newtonsoft.Json;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Concurrent;
using System.Data.SqlTypes;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace SignTinDuc
{
    public class ConnectUsbToken
    {
        private static ConcurrentDictionary<string, string> TempStorage = new ConcurrentDictionary<string, string>();
        #region Kiểm tra lấy DLL tương ứng với thiết bị
        public static string CheckDLLMatchUSB(string arrData, string serial)
        {
            var lstDLL = ScanFolderLoadDll.FindPKCS11DLLs(arrData);
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
                                // kiểm tra seri khớp với mặc định trên web
                                if (tokenInfo != null && tokenInfo.SerialNumber == serial)
                                {
                                    pathDLL = pkcs11LibPath; break;
                                }
                            }
                        }

                    }
                }
            }
            TempStorage.TryAdd("pathDLL", pathDLL);
            return pathDLL;
        }
        #endregion
        #region Kiểm tra đăng nhập thiết bị ký số
        public static Result GetUsbTokenInformation(string[] arrdata, string mess)
        {
            // arr1: Dll , arr2: serial thiết bị 
            Result msg = new Result();
            string pkcs11LibPath = CheckDLLMatchUSB(arrdata[1], arrdata[2]);
            if (pkcs11LibPath == "")
            {
                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy thiết bị USB ký số\"}"), true, true, mess);
            }
            else
            {
                // Khởi tạo thư viện PKCS#11
                Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
                try
                {
                    using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pkcs11LibPath, AppType.SingleThreaded))
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
                            var icon = GetIconFromDll(pkcs11LibPath, 0);
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
                                            //byte[] data = File.ReadAllBytes(filePath);
                                            //byte[] hash = ComputeSha256Hash(data);
                                            //Lấy dữ liệu của chứng chỉ
                                            byte[] certificateData = session.GetAttributeValue(certHandle, new List<CKA> { CKA.CKA_VALUE })[0].GetValueAsByteArray();
                                            //Chuyển đổi dữ liệu thành đối tượng X509Certificate2
                                            var certificate = new X509Certificate2(certificateData);
                                            // chỉ lấy chứng thư số còn hạn sử dụng
                                            if (certificate != null && certificate.NotBefore <= DateTime.Now && certificate.NotAfter >= DateTime.Now)
                                            {
                                                var mechanism = factories.MechanismFactory.Create(CKM.CKM_SHA1_RSA_PKCS);
                                                // chữ ký
                                                //byte[] signature = session.Sign(mechanism, privateKeyHandle, hash);
                                                //SignPdfWithPkcs11(filePath, filePathSign, signature, certificate);
                                                //SignXmlDocument(fileXmlPath, fileSignXml, signature, certificate);
                                                session.Logout();
                                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Kết nối đến USB Token thành công.\"}"), true, true, mess);
                                            }
                                            else
                                            {
                                                session.Logout();
                                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Chứng thư số đã hết hiệu lực.\"}"), true, true, mess);
                                            }
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
        public static Result SignPdfWithPkcs11(byte[] pdfData, byte[] signature, X509Certificate2 certificate)
        {

            // Đọc file PDF gốc với PdfReader
            using (MemoryStream inputStream = new MemoryStream(pdfData))
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
                //PdfSignatureAppearance signatureAppearance = pdfSigner.GetSignatureAppearance()
                //                                                   .SetPageRect(new iText.Kernel.Geom.Rectangle(x, y, width, height))
                //                                                   .SetReason("Digital signature")
                //                                                   .SetLocation("Location")
                //                                                   .SetLayer2Font(font)
                //                                                   ;
                //pdfSigner.SetCertificationLevel(PdfSigner.CERTIFIED_NO_CHANGES_ALLOWED);
                //ITSAClient tsaClient = new TSAClientBouncyCastle("http://tsa.ca.gov.vn");
                // Ký số file PDF
                //pdfSigner.SignDetached(digest, pks, certChain, null, null, tsaClient, 0, PdfSigner.CryptoStandard.CADES);
                pdfSigner.SignDetached(digest, pks, certChain, null, null, null, 0, PdfSigner.CryptoStandard.CADES);
                Result rs = new Result();
                rs.isOk = true;
                rs.Object = outputStream.ToArray();
                return rs;
            }
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

            XmlElement signingTime = xmlDoc.CreateElement("SigningTime", "http://www.w3.org/2000/09/xmldsig#");
            signingTime.InnerText = DateTime.UtcNow.ToString("o"); // ISO 8601 format (UTC)
            signatureProperty.AppendChild(signingTime);

            // Add Base64 Image and Coordinates
            XmlElement signatureImage = xmlDoc.CreateElement("SignatureImage", "http://www.w3.org/2000/09/xmldsig#");
            signatureImage.InnerText = imageBase64;
            objectElement.AppendChild(signatureImage);

            XmlElement signatureCoordinates = xmlDoc.CreateElement("SignatureCoordinates", "http://www.w3.org/2000/09/xmldsig#");
            objectElement.AppendChild(signatureCoordinates);

            XmlElement xCoord = xmlDoc.CreateElement("X", "http://www.w3.org/2000/09/xmldsig#");
            xCoord.InnerText = x.ToString();
            signatureCoordinates.AppendChild(xCoord);

            XmlElement yCoord = xmlDoc.CreateElement("Y", "http://www.w3.org/2000/09/xmldsig#");
            yCoord.InnerText = y.ToString();
            signatureCoordinates.AppendChild(yCoord);

            XmlElement widthElement = xmlDoc.CreateElement("Width", "http://www.w3.org/2000/09/xmldsig#");
            widthElement.InnerText = width.ToString();
            signatureCoordinates.AppendChild(widthElement);

            XmlElement heightElement = xmlDoc.CreateElement("Height", "http://www.w3.org/2000/09/xmldsig#");
            heightElement.InnerText = height.ToString();
            signatureCoordinates.AppendChild(heightElement);

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
                                            var objData = new
                                            {
                                                SerialDevice = SerialDevices,
                                                SerialCertificate = certificate.SerialNumber,
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
        public static Result SignPdfUsbToken(string[] arrdata, string messId)
        {
            // arr1: Dll , arr2: serial thiết bị , arr3: base64 pdf
            Result msg = new Result();
            // lấy lại dll từ biển TempStorage
            string pkcs11LibPath = CheckDLLMatchUSB(arrdata[1], arrdata[2]);
            if (pkcs11LibPath == "")
            {
                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy thiết bị USB ký số\"}"), true, true, messId);
            }
            else
            {
                // Khởi tạo thư viện PKCS#11
                Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
                try
                {
                    using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pkcs11LibPath, AppType.SingleThreaded))
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
                            var icon = GetIconFromDll(pkcs11LibPath, 0);
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
                                            //byte[] data = File.ReadAllBytes(filePath);
                                            //byte[] hash = ComputeSha256Hash(data);
                                            //Lấy dữ liệu của chứng chỉ
                                            byte[] certificateData = session.GetAttributeValue(certHandle, new List<CKA> { CKA.CKA_VALUE })[0].GetValueAsByteArray();
                                            //Chuyển đổi dữ liệu thành đối tượng X509Certificate2
                                            var certificate = new X509Certificate2(certificateData);
                                            // chỉ lấy chứng thư số còn hạn sử dụng
                                            if (certificate != null && certificate.NotBefore <= DateTime.Now && certificate.NotAfter >= DateTime.Now)
                                            {
                                                var mechanism = factories.MechanismFactory.Create(CKM.CKM_SHA1_RSA_PKCS);
                                                // chữ ký
                                                //byte[] signature = session.Sign(mechanism, privateKeyHandle, hash);
                                                //SignPdfWithPkcs11(filePath, filePathSign, signature, certificate);
                                                //SignXmlDocument(fileXmlPath, fileSignXml, signature, certificate);
                                                session.Logout();
                                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Kết nối đến USB Token thành công.\"}"), true, true, messId);
                                            }
                                            else
                                            {
                                                session.Logout();
                                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Chứng thư số đã hết hiệu lực.\"}"), true, true, messId);
                                            }
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
            return msg;
        }
        #endregion
        #region Connect sign xml dùng dữ liệu
        public static Result SignXmlUsbToken(string dll, string serial, string dataBase64,string dataImageBase64, string messId)
        {
            // arr1: Dll , arr2: serial thiết bị , arr3: base64 xml,
            Result msg = new Result();
            // lấy lại dll từ biển TempStorage
            string pkcs11LibPath = CheckDLLMatchUSB(dll, serial);
            if (pkcs11LibPath == "")
            {
                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy thiết bị USB ký số\"}"), true, true, messId);
            }
            else
            {
                // Khởi tạo thư viện PKCS#11
                Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
                try
                {
                    using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pkcs11LibPath, AppType.SingleThreaded))
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
                            var icon = GetIconFromDll(pkcs11LibPath, 0);
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
                                            string base64data = SignXmlDocument(data, signature, certificate, dataImageBase64, 1, 50, 50, 50);

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
        #region Ký nhiều file xml 
        public static Result SignMultipleFileXML(string dll, string serial, string dataBase64, string dataImageBase64, string messId)
        {
            Result msg = new Result();
            // lấy lại dll từ biển TempStorage
            string pkcs11LibPath = CheckDLLMatchUSB(dll, serial);
            if (pkcs11LibPath == "")
            {
                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy thiết bị USB ký số\"}"), true, true, messId);

            }
            else
            {
                Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
                try
                {
                    using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pkcs11LibPath, AppType.SingleThreaded))
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
                            var icon = GetIconFromDll(pkcs11LibPath, 0);
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
        public class Data
        {
            public string? Id { get; set; }
            public string? SignXml { get; set; }
        }
    }
}
