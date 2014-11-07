using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace ITfoxtec.Saml2.Cryptography
{
    public class Saml2EncryptedXml : EncryptedXml
    {
        public RSA DecryptionPrivateKey { get; set; }

        public Saml2EncryptedXml(XmlDocument document)
            : base(document)
        {
            if (document == null)
            {
                throw new ArgumentNullException("document");
            }
        }

        public Saml2EncryptedXml(XmlDocument document, RSA decryptionPrivateKey)
            : this(document)
        {
            if (decryptionPrivateKey == null)
            {
                throw new ArgumentNullException("decryptionPrivateKey");
            }
            DecryptionPrivateKey = decryptionPrivateKey;
        }

        public override byte[] DecryptEncryptedKey(EncryptedKey encryptedKey)
        {
            return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, DecryptionPrivateKey, (encryptedKey.EncryptionMethod != null) && (encryptedKey.EncryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl));
        }

    }
}
