using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Security.Cryptography;

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
            RSACng rsaCng = DecryptionPrivateKey as RSACng;
            if (rsaCng != null)
            {
                byte[] keyData = encryptedKey.CipherData.CipherValue;
                if (keyData == null)
                {
                    throw new ArgumentNullException("encryptedKey");
                }

                if (DecryptionPrivateKey == null)
                {
                    throw new InvalidOperationException("DecryptionPrivateKey is null.");
                }

                AsymmetricPaddingMode paddingMode;
                if (encryptedKey.EncryptionMethod != null &&
                    encryptedKey.EncryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl)
                {
                    paddingMode = AsymmetricPaddingMode.Oaep;
                }
                else
                {
                    paddingMode = AsymmetricPaddingMode.Pkcs1;
                }

                rsaCng.EncryptionPaddingMode = paddingMode;
                rsaCng.EncryptionHashAlgorithm = CngAlgorithm.Sha1;
                return rsaCng.DecryptValue(keyData);
            }

            return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, this.DecryptionPrivateKey, (encryptedKey.EncryptionMethod != null) && (encryptedKey.EncryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl));
        }

    }
}
