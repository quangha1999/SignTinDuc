using iText.Signatures;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI41;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignTinDuc.Utils
{
    public class Pkcs11Signature: IExternalSignature
    {
        private readonly ISession session;
        private readonly IObjectHandle privateKey;
        private readonly string encryptionAlgorithm;
        private readonly string digestAlgorithm;

        public Pkcs11Signature(ISession session, IObjectHandle privateKey, string digestAlgorithm = "SHA-256")
        {
            this.session = session;
            this.privateKey = privateKey;
            this.digestAlgorithm = digestAlgorithm;
            this.encryptionAlgorithm = "RSA";
        }

       

        public string GetEncryptionAlgorithm() => encryptionAlgorithm;
        public string GetHashAlgorithm() => digestAlgorithm;
        public string GetDigestAlgorithmName() => digestAlgorithm;
        public string GetSignatureAlgorithmName() => $"{digestAlgorithm}with{encryptionAlgorithm}";


        public ISignatureMechanismParams GetSignatureMechanismParameters() => null;

        public byte[] Sign(byte[] message)
        {
            // Token tự hash và ký, không cần hash ngoài
            CKM mechanismType = digestAlgorithm switch
            {
                "SHA-256" => CKM.CKM_SHA256_RSA_PKCS,
                "SHA-1" => CKM.CKM_SHA1_RSA_PKCS,
                "SHA-512" => CKM.CKM_SHA512_RSA_PKCS,
                _ => throw new NotSupportedException($"Thuật toán hash {digestAlgorithm} không được hỗ trợ."),
            };

            var mechanism = session.Factories.MechanismFactory.Create(mechanismType);
            return session.Sign(mechanism, privateKey, message);
        }

        private byte[] EncodeDigestInfo(byte[] hash, string digestAlg)
        {
            byte[] digestInfoPrefix;

            if (digestAlg.Equals("SHA-256", StringComparison.OrdinalIgnoreCase))
            {
                digestInfoPrefix = new byte[] {
                0x30, 0x31,
                0x30, 0x0d,
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // OID for SHA-256
                0x05, 0x00,
                0x04, 0x20
            };
            }
            else
            {
                throw new NotImplementedException("Chỉ hỗ trợ SHA-256 hiện tại.");
            }

            return digestInfoPrefix.Concat(hash).ToArray();
        }
    }
}
