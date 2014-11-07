using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace ITfoxtec.Saml2.Cryptography
{
    public class Saml2SignedXml : System.Security.Cryptography.Xml.SignedXml
    {
        public Saml2SignedXml() : base()
        {
            AddAlgorithm();
        }

        public Saml2SignedXml(XmlDocument document) : base(document)
        {
            AddAlgorithm();
        }
        
        public Saml2SignedXml(XmlElement element) : base(element)
        {
            AddAlgorithm();
        }

        private void AddAlgorithm()
        {
            // For SHA256
            //if (CryptoConfig.CreateFromName(SecurityAlgorithms.RsaSha256Signature) == null)
            //{
            //    CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), SecurityAlgorithms.RsaSha256Signature);
            //}
        }

        public void ComputeSignature(X509Certificate2 certificate, X509IncludeOption includeOption, string id)
        {
            SigningKey = (RSACryptoServiceProvider)certificate.PrivateKey;

            SignedInfo.CanonicalizationMethod = Saml2SignedXml.XmlDsigExcC14NTransformUrl;
            //SignedInfo.SignatureMethod = SecurityAlgorithms.RsaSha256Signature;

            var reference = new Reference("#" + id);
            // reference.DigestMethod = SecurityAlgorithms.Sha1Digest;
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());

            AddReference(reference);
            ComputeSignature();

            KeyInfo = new KeyInfo();
            KeyInfo.AddClause(new KeyInfoX509Data(certificate, includeOption));
        }

        public bool CheckSignature(X509Certificate2 certificate)
        {
            try
            {
                return base.CheckSignature(certificate, true);
            }
            catch (CryptographicException cExc)
            {
                throw new CryptographicException("SHA256 algorithm is not supported.", cExc);
            }
        }

        protected new void ComputeSignature()
        {
            base.ComputeSignature();
        }
    }
}
