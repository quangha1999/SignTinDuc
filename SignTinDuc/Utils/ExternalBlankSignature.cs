using iText.Signatures;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignTinDuc
{
    public class ExternalBlankSignature : IExternalSignature
    {
        private readonly byte[] _signature;
        private readonly string _encryptionAlgorithm;
        private readonly string _hashAlgorithm;

        public ExternalBlankSignature(byte[] signature, string encryptionAlgorithm, string hashAlgorithm)
        {
            _signature = signature;
            _encryptionAlgorithm = encryptionAlgorithm;
            _hashAlgorithm = hashAlgorithm;
        }

        public byte[] Sign(byte[] message)
        {
            return _signature;
        }

        public string GetEncryptionAlgorithm()
        {
            return _encryptionAlgorithm;
        }

        public string GetHashAlgorithm()
        {
            return _hashAlgorithm;
        }

        public string GetDigestAlgorithmName()
        {
            return "SHA-256";
        }

        public string GetSignatureAlgorithmName()
        {
            return "RSA";
        }

        public ISignatureMechanismParams GetSignatureMechanismParameters()
        {
            return null;
        }
    }
}
