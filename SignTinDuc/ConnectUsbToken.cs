using iText.Bouncycastle.X509;
using iText.Commons.Bouncycastle.Cert;
using iText.Forms;
using iText.IO.Font;
using iText.Kernel.Font;
using iText.Kernel.Pdf;
using iText.Signatures;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.X509;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace SignTinDuc
{
    public class ConnectUsbToken
    {
        static string PKCS11LibPath = @"E:\Code\PluginSign\nca_v6.dll";
        static string filePath = @"E:\Code\PluginSign\export-pdf-demo.pdf";
        static string filePathSign = @"E:\Code\PluginSign\export-pdf-sign.pdf";
        static string fileXmlPath = @"E:\Code\PluginSign\export-xml-sign.xml";
        static string fileSignXml = @"E:\Code\PluginSign\export-xml-sign-g.xml";
        /// <summary>
        /// Lấy thông tin thiết bị usbtoken
        /// </summary>
        /// <param name="pkcs11LibPath"></param>
        public static void GetUsbTokenInformation(string pkcs11LibPath, string password)
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
                    // Mở session và đăng nhập vào token
                    using (ISession session = slot.OpenSession(SessionType.ReadOnly))
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
                        // chỉ lấy chứng thư số còn hạn sử dụng
                        // nếu đã hết hạn thì cảnh báo lỗi
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
                            byte[] data = File.ReadAllBytes(filePath);
                            byte[] hash = ComputeSha256Hash(data);
                            //Lấy dữ liệu của chứng chỉ
                            byte[] certificateData = session.GetAttributeValue(certHandle, new List<CKA> { CKA.CKA_VALUE })[0].GetValueAsByteArray();
                            //Chuyển đổi dữ liệu thành đối tượng X509Certificate2
                            var certificate = new X509Certificate2(certificateData);
                            var mechanism = factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS);
                            // chữ ký
                            byte[] signature = session.Sign(mechanism, privateKeyHandle, hash);
                            SignPdfWithPkcs11(filePath, filePathSign, signature, certificate);
                            SignXmlDocument(fileXmlPath, fileSignXml, signature, certificate);
                            Console.WriteLine("File đã được ký thành công!");
                        }
                        else
                        {
                            Console.WriteLine("Không tìm thấy khóa cá nhân trên token.");
                        }

                        session.Logout();
                    }

                }
            }
        }
        // Hàm tính toán SHA-256 hash của dữ liệu
        private static byte[] ComputeSha256Hash(byte[] data)
        {
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                return sha256.ComputeHash(data);
            }
        }
        private byte[] GetSignatureFromHashViaPkcs11(byte[] hash, string pin)
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
        public static void SignPdfWithPkcs11(string pdfPath, string signedPdfPath, byte[] signature, X509Certificate2 certificate)
        {

            // Đọc file PDF gốc với PdfReader
            using (PdfReader pdfReader = new PdfReader(pdfPath))
            using (FileStream outputStream = new FileStream(signedPdfPath, FileMode.Create))
            {
                // Tạo đối tượng PdfSigner để xử lý ký số
                PdfSigner pdfSigner = new PdfSigner(pdfReader, outputStream, new StampingProperties());

                IExternalSignature pks = new ExternalBlankSignature(signature, "RSA", "SHA-256");
                IExternalDigest digest = new BouncyCastleDigest();

                // Chuyển đổi X509Certificate2 của .NET thành BouncyCastle X509Certificate
                Org.BouncyCastle.X509.X509Certificate bouncyCert = ConvertToBouncyCastleCertificate(certificate);

                // Chuyển đổi thành iText IX509Certificate
                IX509Certificate iTextCert = new X509CertificateBC(bouncyCert);
                float x = 595 - 150; // Vị trí X, 595 là chiều rộng của A4, 150 là chiều rộng chữ ký
                float y = 842 - 50;  // Vị trí Y, 842 là chiều cao của A4, 50 là chiều cao chữ ký
                float width = 150;   // Chiều rộng chữ ký
                float height = 50;   // Chiều cao chữ ký
                string baseDirectory = Directory.GetParent(AppDomain.CurrentDomain.BaseDirectory).Parent.Parent.FullName;
                string fontPath = Path.Combine(baseDirectory, "TIMES.ttf");
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
                ITSAClient tsaClient = new TSAClientBouncyCastle("http://tsa.ca.gov.vn");
                // Ký số file PDF
                pdfSigner.SignDetached(digest, pks, certChain, null, null, tsaClient, 0, PdfSigner.CryptoStandard.CADES);
            }
        }
        public static void SignXmlDocument(string xmlFilePath, string signedXmlFilePath, byte[] signature, X509Certificate2 certificate)
        {
            // Tạo đối tượng XmlDocument từ file XML gốc
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load(xmlFilePath);

            // Create the Signature XML element
            XmlElement signatureElement = xmlDoc.CreateElement("Signature", "http://www.w3.org/2000/09/xmldsig#");

            // Create the SignedInfo element
            XmlElement signedInfoElement = xmlDoc.CreateElement("SignedInfo", "http://www.w3.org/2000/09/xmldsig#");
            signatureElement.AppendChild(signedInfoElement);

            // Create and append the CanonicalizationMethod element
            XmlElement canonicalizationMethod = xmlDoc.CreateElement("CanonicalizationMethod", "http://www.w3.org/2000/09/xmldsig#");
            canonicalizationMethod.SetAttribute("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
            signedInfoElement.AppendChild(canonicalizationMethod);

            // Create and append the SignatureMethod element
            XmlElement signatureMethod = xmlDoc.CreateElement("SignatureMethod", "http://www.w3.org/2000/09/xmldsig#");
            signatureMethod.SetAttribute("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            signedInfoElement.AppendChild(signatureMethod);

            // Create and append the Reference element
            XmlElement reference = xmlDoc.CreateElement("Reference", "http://www.w3.org/2000/09/xmldsig#");
            reference.SetAttribute("URI", "");
            signedInfoElement.AppendChild(reference);

            // Create and append the DigestMethod element
            XmlElement digestMethod = xmlDoc.CreateElement("DigestMethod", "http://www.w3.org/2000/09/xmldsig#");
            digestMethod.SetAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
            reference.AppendChild(digestMethod);

            // Create and append the DigestValue element (Dummy value, you can replace it as per your requirement)
            XmlElement digestValue = xmlDoc.CreateElement("DigestValue", "http://www.w3.org/2000/09/xmldsig#");
            digestValue.InnerText = Convert.ToBase64String(new byte[32]);  // Placeholder value
            reference.AppendChild(digestValue);

            // Append the SignatureValue element
            XmlElement signatureValueElement = xmlDoc.CreateElement("SignatureValue", "http://www.w3.org/2000/09/xmldsig#");
            signatureValueElement.InnerText = Convert.ToBase64String(signature);
            signatureElement.AppendChild(signatureValueElement);

            // Create and append the KeyInfo element
            XmlElement keyInfoElement = xmlDoc.CreateElement("KeyInfo", "http://www.w3.org/2000/09/xmldsig#");
            signatureElement.AppendChild(keyInfoElement);

            // Create and append the X509Data element
            XmlElement x509Data = xmlDoc.CreateElement("X509Data", "http://www.w3.org/2000/09/xmldsig#");
            keyInfoElement.AppendChild(x509Data);

            // Add the certificate
            XmlElement x509CertificateElement = xmlDoc.CreateElement("X509Certificate", "http://www.w3.org/2000/09/xmldsig#");
            x509CertificateElement.InnerText = Convert.ToBase64String(certificate.Export(X509ContentType.Cert));
            x509Data.AppendChild(x509CertificateElement);

            // Append the Signature element to the XML document
            xmlDoc.DocumentElement.AppendChild(signatureElement);

            // Save the signed XML document to a file
            xmlDoc.Save(signedXmlFilePath);




            //// Tạo đối tượng SignedXml từ XmlDocument
            //SignedXml signedXml = new SignedXml(xmlDoc);

            //signedXml.SigningKey = certificate.GetRSAPublicKey();
            //signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

            //signedXml.Signature.SignatureValue = signature;
            //// Tạo đối tượng Reference để chỉ định phần tử XML sẽ được ký
            //Reference reference = new Reference();
            //reference.Uri = "";
            //// Tạo đối tượng CanonicalizationMethod và SignatureMethod
            //reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            //signedXml.AddReference(reference);
            //reference.DigestMethod = SignedXml.XmlDsigSHA256Url;
            //// Thêm thông tin chứng chỉ vào phần KeyInfo (để người nhận có thể kiểm tra chữ ký)
            //KeyInfo keyInfo = new KeyInfo();
            //keyInfo.AddClause(new KeyInfoX509Data(certificate)); // Lấy chứng chỉ từ session hoặc handle
            //signedXml.KeyInfo = keyInfo;


            //// Thêm chữ ký vào XML
            //XmlElement xmlSignature = signedXml.GetXml();
            //xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlSignature, true));

            // Lưu tệp XML đã ký
            //xmlDoc.Save(signedXmlFilePath);
            Console.WriteLine("XML file signed successfully.");
        }
        public static Org.BouncyCastle.X509.X509Certificate ConvertToBouncyCastleCertificate(X509Certificate2 cert)
        {
            var certParser = new X509CertificateParser();
            return certParser.ReadCertificate(cert.RawData);
        }
        public void VerifyPdfSignature(string pdfPath)
        {
            // Đọc tài liệu PDF đã ký
            using (PdfReader pdfReader = new PdfReader(pdfPath))
            using (PdfDocument pdfDoc = new PdfDocument(pdfReader))
            {
                // Lấy đối tượng PdfAcroForm để truy xuất các trường trong PDF
                var acroForm = PdfAcroForm.GetAcroForm(pdfDoc, false);
                var fieldNames = acroForm.GetAllFormFields().Keys;

                // Kiểm tra từng trường và xác định nếu nó là một chữ ký
                foreach (var fieldName in fieldNames)
                {
                    Console.WriteLine("Field Name: " + fieldName);

                    // Nếu trường là chữ ký, xác minh chữ ký đó
                    //if (acroForm.GetField(fieldName).GetFormType() == PdfFormField.FORM_TYPE_SIGNATURE)
                    //{
                    //PdfSignature signature = pdfDoc.Get(fieldName);
                    //Console.WriteLine("Signature found in field: " + fieldName);

                    // Lấy chứng chỉ của người ký
                    //var signerCert = signature.GetSignerCertificate();
                    //Console.WriteLine("Signer Certificate: " + signerCert.SubjectDN);
                    //Console.WriteLine("Signature Algorithm: " + signature.GetSignatureAlgorithm());
                    //Console.WriteLine("Digest Algorithm: " + signature.GetDigestAlgorithm());

                    //// Kiểm tra tính hợp lệ của chữ ký
                    //bool isValid = signature.VerifySignature();
                    //Console.WriteLine("Signature is valid: " + isValid);
                    //}
                }
            }
        }

    }
    public class SmartCardSlot
    {
        public string TokenSerial { get; set; }
    }
}
