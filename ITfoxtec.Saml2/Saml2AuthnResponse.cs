using ITfoxtec.Saml2.Extensions;
using ITfoxtec.Saml2.Schemas;
using ITfoxtec.Saml2.Tokens;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Xml;
using System.Xml.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Globalization;
using ITfoxtec.Saml2.Util;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Selectors;
using ITfoxtec.Saml2.Cryptography;
using System.Security.Cryptography;
using System.Diagnostics;

namespace ITfoxtec.Saml2
{
    /// <summary>
    /// Saml2 Authn Response.
    /// </summary>
    public class Saml2AuthnResponse : Saml2Response
    {
        const string elementName = Saml2Constants.Message.AuthnResponse;

        internal X509Certificate2 DecryptionCertificate { get; private set; }

        public Saml2AuthnResponse(X509Certificate2 decryptionCertificate = null)
        {
            if (decryptionCertificate != null)
            {
                DecryptionCertificate = decryptionCertificate;
                if (decryptionCertificate.PrivateKey == null)
                {
                    throw new ArgumentException("No Private Key present in Decryption Certificate or missing private key read credentials.");
                }
                if (!(decryptionCertificate.PrivateKey is RSA))
                {
                    throw new ArgumentException("The Private Key present in Decryption Certificate must be RSA.");
                }
            }
            Saml2SecurityTokenHandler = Saml2ResponseSecurityTokenHandler.GetSaml2SecurityTokenHandler();
        }

        /// <summary>
        /// Claims Identity.
        /// </summary>
        public ClaimsIdentity ClaimsIdentity { get; set; }

        /// <summary>
        /// Saml2 Security Token.
        /// </summary>
        public Saml2SecurityToken Saml2SecurityToken { get; protected set; }

        /// <summary>
        /// Saml2 Security Token Handler.
        /// </summary>
        public Saml2SecurityTokenHandler Saml2SecurityTokenHandler { get; protected set; }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != elementName)
            {
                throw new Saml2ResponseException("Not a SAML2 Authn Response.");
            }
        }

        public override XmlDocument ToXml()
        {
            throw new NotImplementedException();
        }

        internal override void Read(string xml, bool validateXmlSignature = false, TimeSpan? clockTolerance = null)
        {
            base.Read(xml, validateXmlSignature);

            if (Status == Saml2StatusCodes.Success)
            {
                var assertionElement = GetAssertionElement();
                ValidateAssertionExpiration(assertionElement, clockTolerance: clockTolerance);

                Saml2SecurityToken = ReadSecurityToken(assertionElement);
                ClaimsIdentity = ReadClaimsIdentity();
            }
        }

        private XmlNode GetAssertionElement()
        {
            var assertionElements = XmlDocument.DocumentElement.SelectNodes(string.Format("//*[local-name()='{0}']", Saml2Constants.Message.Assertion)); 
            if (assertionElements.Count != 1)
            {
                throw new Saml2ResponseException("There is not exactly one Assertion element.");
            }
            return assertionElements[0];
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="assertionElement"></param>
        /// <param name="clockTolerance">Allow for clock slip of this amount (on top of what the IDP already includes in the NotOnOrAfter assertion)</param>
        private void ValidateAssertionExpiration(XmlNode assertionElement, TimeSpan? clockTolerance = null)
        {
            var subjectElement = assertionElement[Saml2Constants.Message.Subject, Saml2Constants.AssertionNamespace.OriginalString];
            if(subjectElement == null)
            {
                throw new Saml2ResponseException("Subject Not Found.");
            }
            var subjectConfirmationElement = subjectElement[Saml2Constants.Message.SubjectConfirmation, Saml2Constants.AssertionNamespace.OriginalString];
            if(subjectConfirmationElement == null)
            {
                throw new Saml2ResponseException("SubjectConfirmationElement Not Found.");
            }
            var subjectConfirmationData = subjectConfirmationElement[Saml2Constants.Message.SubjectConfirmationData, Saml2Constants.AssertionNamespace.OriginalString];
            if(subjectConfirmationData == null)
            {
                throw new Saml2ResponseException("SubjectConfirmationData Not Found.");
            }

            var notOnOrAfter = DateTime.Parse(subjectConfirmationData.Attributes[Saml2Constants.Message.NotOnOrAfter].GetValueOrNull(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal);

            if (clockTolerance.HasValue)
            {
                // 'Add' the tolerance to the assertion date
                notOnOrAfter += clockTolerance.Value;
            }

            if (notOnOrAfter < DateTime.UtcNow)
            {
                throw new Saml2ResponseException(string.Format("Assertion has expired. Assertion valid NotOnOrAfter {0}.", notOnOrAfter));
            }
        }

        private Saml2SecurityToken ReadSecurityToken(XmlNode assertionElement)
        {
            using (var reader = new XmlNodeReader(assertionElement))
            {
                return Saml2SecurityTokenHandler.ReadToken(reader) as Saml2SecurityToken;
            }
        }

        private ClaimsIdentity ReadClaimsIdentity()
        {
            return Saml2SecurityTokenHandler.ValidateToken(Saml2SecurityToken).First();
        }

        protected override void DecryptMessage()
        {
            if(DecryptionCertificate != null)
            {
                new Saml2EncryptedXml(XmlDocument, DecryptionCertificate.PrivateKey as RSA).DecryptDocument();
#if DEBUG
                Debug.WriteLine("Saml2P (Decrypted): " + XmlDocument.OuterXml);
#endif
            }
        }
    }
}
