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
        public static Result GetUsbTokenInformation(string[] arrdata)
        {
            // arr1: Dll , arr2: serial thiết bị 
            Result msg = new Result();
            string pkcs11LibPath = CheckDLLMatchUSB(arrdata[1], arrdata[2]);
            if (pkcs11LibPath == "")
            {
                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy thiết bị USB ký số\"}"), true, true);
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
                                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Kết nối đến USB Token thành công.\"}"), true, true);
                                            }
                                            else
                                            {
                                                session.Logout();
                                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Chứng thư số đã hết hiệu lực.\"}"), true, true);
                                            }
                                        }
                                        else
                                        {
                                            session.Logout();
                                            msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy khóa cá nhân trên token\"}"), true, true);
                                        }
                                    }
                                    catch (Exception e)
                                    {
                                        msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn nhập sai mã PIN\"}"), true, true);
                                    }
                                }
                            }
                            else
                            {
                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn chưa nhập mã PIN\"}"), true, true);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không kết nối được USB ký số\"}"), true, true);
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
            foreach(var bytedata in multipleDatas)
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
        public static Result GetInformationDevices(string arrdata)
        {
            Result msg = new Result();
            var lstDLL = ScanFolderLoadDll.FindPKCS11DLLs(arrdata);
            // dll hoạt động bình thường
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
                                if (tokenInfo != null)
                                {
                                    pathDLL = pkcs11LibPath; break;
                                }
                            }
                        }

                    }
                }
            }
            if (pathDLL == "")
            {
                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy thiết bị USB ký số\"}"), true, true);
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
                                            if (certificate != null && certificate.NotBefore <= DateTime.Now && certificate.NotAfter >= DateTime.Now)
                                            {
                                                var mechanism = factories.MechanismFactory.Create(CKM.CKM_SHA1_RSA_PKCS);
                                                session.Logout();
                                                msg = new Result((int)ResultStatus.OK, JsonConvert.DeserializeObject("{\"Message\":\"Kết nối đến USB Token thành công.\",\"Obj\":\"Kết nối đến USB Token thành công.\"}"), true, true);
                                            }
                                            else
                                            {
                                                session.Logout();
                                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Chứng thư số đã hết hiệu lực.\"}"), true, true);
                                            }
                                        }
                                        else
                                        {
                                            session.Logout();
                                            msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy khóa cá nhân trên token\"}"), true, true);
                                        }
                                    }
                                    catch (Exception e)
                                    {
                                        msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn nhập sai mã PIN\"}"), true, true);
                                    }
                                }
                            }
                            else
                            {
                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn chưa nhập mã PIN\"}"), true, true);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không kết nối được USB ký số\"}"), true, true);
                }
            }
            //return pathDLL;
            return msg;
        }
        #endregion
        #region Connect and sign pdf dùng dữ liệu dll từ TempStorage
        public static Result SignPdfUsbToken(string[] arrdata)
        {
            // arr1: Dll , arr2: serial thiết bị , arr3: base64 pdf
            Result msg = new Result();
            // lấy lại dll từ biển TempStorage
            string pkcs11LibPath = CheckDLLMatchUSB(arrdata[1], arrdata[2]);
            if (pkcs11LibPath == "")
            {
                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy thiết bị USB ký số\"}"), true, true);
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
                                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Kết nối đến USB Token thành công.\"}"), true, true);
                                            }
                                            else
                                            {
                                                session.Logout();
                                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Chứng thư số đã hết hiệu lực.\"}"), true, true);
                                            }
                                        }
                                        else
                                        {
                                            session.Logout();
                                            msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy khóa cá nhân trên token\"}"), true, true);
                                        }
                                    }
                                    catch (Exception e)
                                    {
                                        msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn nhập sai mã PIN\"}"), true, true);
                                    }
                                }
                            }
                            else
                            {
                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn chưa nhập mã PIN\"}"), true, true);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không kết nối được USB ký số\"}"), true, true);
                }
            }
            return msg;
        }
        #endregion
        #region Connect sign xml dùng dữ liệu dll từ tempstorage
        public static Result SignXmlUsbToken(string dll, string serial, string dataBase64)
        {
            // arr1: Dll , arr2: serial thiết bị , arr3: base64 xml,
            Result msg = new Result();
            // lấy lại dll từ biển TempStorage
            string pkcs11LibPath = CheckDLLMatchUSB(dll, serial);
            if (pkcs11LibPath == "")
            {
                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy thiết bị USB ký số\"}"), true, true);
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
                                            if (certificate != null && certificate.NotBefore <= DateTime.Now && certificate.NotAfter >= DateTime.Now)
                                            {
                                                var mechanism = factories.MechanismFactory.Create(CKM.CKM_SHA1_RSA_PKCS);
                                                // chữ ký
                                                byte[] signature = session.Sign(mechanism, privateKeyHandle, hash);
                                                //SignPdfWithPkcs11(filePath, filePathSign, signature, certificate);
                                                string base64Image = "iVBORw0KGgoAAAANSUhEUgAAAfQAAAFNCAYAAAD2E503AAAAAXNSR0IArs4c6QAAIABJREFUeF7snXdUVMkWr8/pnAM0qZucM6JgxqyIOSLmjBkFRRADGREMCCZExTyKM445zYxgwDFhJEmQnDOSobvfKx9z39y5OqKCYLt7LZZ/eELVt/epX9Wuql04Bj8gAASAABAAAkDguyeAf/c1gAoAASAABIAAEAACGAg6OAEQAAJAAAgAARkgAIIuA0aEKgABIAAEgAAQAEEHHwACQAAIAAEgIAMEQNBlwIhQBSAABIAAEAACIOjgA0AACAABIAAEZIAACLoMGBGqAASAABAAAkAABB18AAgAASAABICADBAAQZcBI0IVgAAQAAJAAAiAoIMPAAEgAASAABCQAQIg6DJgRKgCEAACQAAIAAEQdPABIAAEgAAQAAIyQAAEXQaMCFUAAkAACAABIACCDj4ABIAAEAACQEAGCICgy4ARoQpAAAgAASAABEDQwQeAABAAAkAACMgAARB0GTAiVAEIAAEgAASAAAg6+AAQAAJAAAgAARkgAIIuA0aEKgABIAAEgAAQAEEHHwACQAAIAAEgIAMEQNBlwIhQBSAABIAAEAACIOjgA0AACAABIAAEZIAACLoMGBGqAASAABAAAkAABB18AAgAASAABICADBAAQZcBI0IVgAAQAAJAAAiAoIMPAAEgAASAABCQAQIg6DJgRKgCEAACQAAIAAEQdPABIAAEgAAQAAIyQAAEXQaMCFUAAkAACAABIACCDj4ABIAAEAACQEAGCICgy4ARoQpAAAgAASAABEDQwQeAABAAAkAACMgAARB0GTAiVAEIAAEgAASAAAg6+AAQAAJAAAgAARkgAIIuA0aEKgABIAAEgAAQAEEHHwACQAAIAAEgIAMEQNBlwIhQBSAABIAAEAACIOjgA0AACAABIAAEZIAACLoMGBGqAASAABAAAkAABB18AAgAASAABICADBAAQZcBI0IVgAAQAAJAAAiAoIMPAAEgAASAABCQAQIg6DJgRKgCEAACQAAIAAEQdPABIAAEgAAQAAIyQAAEXQaMCFUAAkAACAABIACCDj4ABIAAEAACQEAGCICgy4ARoQpAAAgAASAABEDQwQeAABAAAkAACMgAARB0GTAiVAEIAAEgAASAAAg6+AAQAAJAAAgAARkgAIIu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";
                                                string base64data=SignXmlDocument(data, signature, certificate, base64Image,1,50,50,50);

                                                var response = new { Message = base64data };
                                                string json = JsonConvert.SerializeObject(response);
                                                msg = new Result((int)ResultStatus.OK, json, true, true);
                                                session.Logout();
                                            }
                                            else
                                            {
                                                session.Logout();
                                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Chứng thư số đã hết hiệu lực.\"}"), true, true);
                                            }
                                        }
                                        else
                                        {
                                            session.Logout();
                                            msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không tìm thấy khóa cá nhân trên token\"}"), true, true);
                                        }
                                    }
                                    catch (Exception e)
                                    {
                                        msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn nhập sai mã PIN\"}"), true, true);
                                    }
                                }
                            }
                            else
                            {
                                msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Bạn chưa nhập mã PIN\"}"), true, true);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    msg = new Result((int)ResultStatus.ERROR, JsonConvert.DeserializeObject("{\"Message\":\"Không kết nối được USB ký số\"}"), true, true);
                }
            }
            return msg;
        }
        #endregion
    }
}
