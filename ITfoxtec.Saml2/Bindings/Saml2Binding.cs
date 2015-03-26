using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Xml;
using Security.Cryptography;
using Security.Cryptography.X509Certificates;

namespace ITfoxtec.Saml2.Bindings
{
    public abstract class Saml2Binding
    {
        public XmlDocument XmlDocument { get; protected set; }

        /// <summary>
        /// <para>Sets the relaystate of the message.</para>
        /// <para>If the message being built is a response message, the relaystate will be included unmodified.</para>
        /// <para>If the message being built is a request message, the relaystate will be encoded and compressed before being included.</para>
        /// </summary>
        public string RelayState { get; set; }

        public Saml2Binding()
        { }

        protected virtual Saml2Binding BindInternal(Saml2Request saml2RequestResponse, X509Certificate2 signingCertificate)
        {
            if (saml2RequestResponse == null)
                throw new ArgumentNullException("saml2RequestResponse");

            if (signingCertificate != null)
            {
                if (signingCertificate.HasCngKey())
                {
                    CngKey privateKey = signingCertificate.GetCngPrivateKey();
                    if (privateKey == null)
                    {
                        throw new ArgumentException("No Private Key present in Signing Certificate or missing private key read credentials.");
                    }

                    if (privateKey.Algorithm.Algorithm != "RSA")
                    {
                        throw new ArgumentException("The Private Key present in Signing Certificate must be RSA.");
                    }
                }
                else
                {
                    if (signingCertificate.PrivateKey == null)
                    {
                        throw new ArgumentException("No Private Key present in Signing Certificate or missing private key read credentials.");
                    }

                    if (!(signingCertificate.PrivateKey is DSA || signingCertificate.PrivateKey is RSACryptoServiceProvider))
                    {
                        throw new ArgumentException("The Private Key present in Signing Certificate must be either DSA or RSACryptoServiceProvider.");
                    }
                }
            }

            XmlDocument = saml2RequestResponse.ToXml();

#if DEBUG
            Debug.WriteLine("Saml2P: " + XmlDocument.OuterXml);
#endif
            return this;
        }

        protected Saml2Request UnbindInternal(HttpRequestBase request, Saml2Request saml2RequestResponse, X509Certificate2 signatureValidationCertificate)
        {
            if (request == null)
                throw new ArgumentNullException("request");

            if (saml2RequestResponse == null)
                throw new ArgumentNullException("saml2RequestResponse");

            if (signatureValidationCertificate == null)
            {
                throw new ArgumentNullException("signatureValidationCertificate");
            }
            if (signatureValidationCertificate.PublicKey == null)
            {
                throw new ArgumentException("No Public Key present in Signature Validation Certificate.");
            }
            if (!(signatureValidationCertificate.PublicKey.Key is DSA || signatureValidationCertificate.PublicKey.Key is RSACryptoServiceProvider))
            {
                throw new ArgumentException("The Public Key present in Signature Validation Certificate must be either DSA or RSACryptoServiceProvider.");
            }

            saml2RequestResponse.SignatureValidationCertificate = signatureValidationCertificate;

            return saml2RequestResponse;
        }

    }
}
