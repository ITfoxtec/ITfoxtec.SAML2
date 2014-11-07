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
    /// Saml2 IdP Initiated Authn Response.
    /// </summary>
    public class Saml2IdPInitiatedAuthnResponse : Saml2AuthnResponse
    {
        const string elementName = Saml2Constants.Message.AuthnResponse;

        public Saml2IdPInitiatedAuthnResponse()
        {
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
            throw new NotImplementedException();
        }

        public override XmlDocument ToXml()
        {
            XmlDocument = new XmlDocument();
            using (XmlWriter xmlWriter = XmlDocument.CreateNavigator().AppendChild())
            {
                xmlWriter.WriteStartElement(elementName, Saml2Constants.ProtocolNamespace.OriginalString);
                xmlWriter.WriteAttributeString(Saml2Constants.Message.IssueInstant, IssueInstant.ToString("o", CultureInfo.InvariantCulture));
                xmlWriter.WriteAttributeString(Saml2Constants.Message.Id, Id.Value);
                xmlWriter.WriteAttributeString(Saml2Constants.Message.Version, Version);

                xmlWriter.WriteStartElement(Saml2Constants.Message.Status);
                xmlWriter.WriteStartElement(Saml2Constants.Message.StatusCode);
                xmlWriter.WriteAttributeString(Saml2Constants.Message.Value, Saml2StatusCodeUtil.ToString(Status));
                xmlWriter.WriteEndElement();
                xmlWriter.WriteEndElement();

                Saml2SecurityTokenHandler.WriteToken(xmlWriter, Saml2SecurityToken);

                xmlWriter.WriteEndElement();
            }

            return XmlDocument;
        }

        internal override void Read(string xml, bool validateXmlSignature = false)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Creates the Security Token and add it to the response.
        /// </summary>
        /// <param name="signingCertificate">The Signing Certificate.</param>
        /// <param name="subjectConfirmationLifetime">The Subject Confirmation Lifetime in minutes.</param>
        /// <param name="issuedTokenLifetime">The Issued Token Lifetime in minutes.</param>
        /// <returns></returns>
        public Saml2SecurityToken CreateSecurityToken(X509Certificate2 signingCertificate, int subjectConfirmationLifetime = 5, int issuedTokenLifetime = 60)
        {
            if (signingCertificate == null)
            {
                throw new ArgumentNullException("signingCertificate");
            }
            if (ClaimsIdentity == null)
            {
                throw new ArgumentNullException("ClaimsIdentity property");
            }
            if (Destination == null)
            {
                throw new ArgumentNullException("Destination property");
            }
            if (Issuer == null)
            {
                throw new ArgumentNullException("Issuer property");
            }

            var tokenDescriptor = CreateTokenDescriptor(ClaimsIdentity.Claims, signingCertificate, issuedTokenLifetime);
            Saml2SecurityToken = Saml2SecurityTokenHandler.CreateToken(tokenDescriptor) as Saml2SecurityToken;

            AddAuthenticationStatement();
            AddSubjectConfirmationData(subjectConfirmationLifetime);

            return Saml2SecurityToken;
        }

        private SecurityTokenDescriptor CreateTokenDescriptor(IEnumerable<Claim> claims, X509Certificate2 signingCertificate, int issuedTokenLifetime)
        {
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                TokenType = SamlTokenTypes.Saml2TokenProfile11.OriginalString,
                Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddMinutes(issuedTokenLifetime)),
                Subject = new ClaimsIdentity(claims),
                AppliesToAddress = Destination.Uri.OriginalString,
                TokenIssuerName = Issuer.Uri.OriginalString,
                SigningCredentials = new X509SigningCredentials(signingCertificate),
            };

            return tokenDescriptor;
        }

        private void AddSubjectConfirmationData(int subjectConfirmationLifetime)
        {
            var subjectConfirmationData = new Saml2SubjectConfirmationData
            {
                Recipient = Destination.Uri,
                NotOnOrAfter = DateTime.UtcNow.AddMinutes(subjectConfirmationLifetime),
            };

            Saml2SecurityToken.Assertion.Subject.SubjectConfirmations.Clear();
            Saml2SecurityToken.Assertion.Subject.SubjectConfirmations.Add(new Saml2SubjectConfirmation(Saml2Constants.Saml2BearerToken, subjectConfirmationData));
        }

        private void AddAuthenticationStatement()
        {
            var authenticationStatement = new Saml2AuthenticationStatement(new Saml2AuthenticationContext(AuthnContextClassTypes.UserNameAndPassword));
            Saml2SecurityToken.Assertion.Statements.Add(authenticationStatement);
        }
    }
}
