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

                // Whether to use OAEP padding or PKCS#1 v1.5 padding as described in the PKCS specification
                if (encryptedKey.EncryptionMethod != null &&
                    encryptedKey.EncryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl)
                {
                    rsaCng.EncryptionPaddingMode = AsymmetricPaddingMode.Oaep;
                }
                else
                {
                    rsaCng.EncryptionPaddingMode = AsymmetricPaddingMode.Pkcs1;
                }

                // Read the XML to figure out if SHA1 or SHA256 is used.
                rsaCng.EncryptionHashAlgorithm = CngAlgorithm.Sha1;
                XmlNode encryptionMethodNode = encryptedKey.GetXml().ChildNodes.Cast<XmlNode>().SingleOrDefault(n => n.LocalName == "EncryptionMethod");
                if (encryptionMethodNode != null)
                {
                    XmlNode digestMethodNode = encryptionMethodNode.ChildNodes.Cast<XmlNode>().SingleOrDefault(n => n.LocalName == "DigestMethod");
                    XmlAttribute digestMethodAttribute = digestMethodNode.Attributes["Algorithm"];
                    if (digestMethodAttribute != null)
                    {
                        string digestMethod = digestMethodAttribute.Value;
                        switch (digestMethod)
                        {
                            case "http://www.w3.org/2000/09/xmldsig#sha1":
                                rsaCng.SignatureHashAlgorithm = CngAlgorithm.Sha1;
                                break;

                            case "http://www.w3.org/2001/04/xmlenc#sha256":
                                rsaCng.SignatureHashAlgorithm = CngAlgorithm.Sha256;
                                break;

                            default:
                                throw new NotSupportedException("Only SHA1 and SHA256 is supported.");
                        }
                    }
                }

                return rsaCng.DecryptValue(keyData);
            }

            return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, this.DecryptionPrivateKey, (encryptedKey.EncryptionMethod != null) && (encryptedKey.EncryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl));
        }

    }
}
