namespace ITfoxtec.Saml2
{
    using ITfoxtec.Saml2.Schemas;
    using ITfoxtec.Saml2.Tokens;
    using System;
    using System.Security.Claims;
    using System.Xml;
    using System.Security.Cryptography.X509Certificates;
    using System.Globalization;
    using ITfoxtec.Saml2.Util;
    using System.IdentityModel.Tokens;
    using System.IdentityModel.Protocols.WSTrust;
    
    /// <summary>
    /// Saml2 IdP Initiated Authn Response.
    /// </summary>
    public class Saml2IdPInitiatedAuthnResponse : Saml2AuthnResponse
    {
        const string elementName = Saml2Constants.Message.AuthnResponse;

        public Saml2IdPInitiatedAuthnResponse()
        {
            Saml2SecurityTokenHandler = Saml2ResponseSecurityTokenHandler.GetSaml2SecurityTokenHandler();
            this.AuthenticationContextClassType = AuthnContextClassTypes.UserNameAndPassword;
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

        /// <summary>
        /// The Audience Uri.
        /// </summary>
        public string AppliesTo { get; set; }

        public Uri AuthenticationContextClassType { get; set; }

        protected override void ValidateElementName()
        {
            throw new NotImplementedException();
        }

        public override XmlDocument ToXml()
        {
            XmlDocument = new XmlDocument();
            XmlDocument.XmlResolver = null;
            XmlDocument.PreserveWhitespace = true;
            using (XmlWriter xmlWriter = XmlDocument.CreateNavigator().AppendChild())
            {
                this.WriteXmlBeforeAssertion(xmlWriter);
                Saml2SecurityTokenHandler.WriteToken(xmlWriter, Saml2SecurityToken);
                WriteXmlAfterAssertion(xmlWriter);
            }

            return XmlDocument;
        }

        public override XmlDocument ToUnencryptedXml()
        {
            Saml2Assertion assertion = this.Saml2SecurityToken.Assertion;
            if (assertion.EncryptingCredentials != null)
            {
                Saml2Assertion copiedAssertion = new Saml2Assertion(assertion.Issuer)
                {
                    Advice = assertion.Advice,
                    Conditions = assertion.Conditions,
                    Id = assertion.Id,
                    IssueInstant = assertion.IssueInstant,
                    SigningCredentials = assertion.SigningCredentials,
                    Subject = assertion.Subject
                };

                foreach (Saml2Statement saml2Statement in assertion.Statements)
                {
                    copiedAssertion.Statements.Add(saml2Statement);
                }

                Saml2SecurityToken tokenWithoutEncryption = new Saml2SecurityToken(copiedAssertion);

                XmlDocument document = new XmlDocument();
                using (XmlWriter xmlWriter = document.CreateNavigator().AppendChild())
                {
                    this.WriteXmlBeforeAssertion(xmlWriter);
                    xmlWriter.WriteStartElement(Saml2Constants.Message.EncryptedAssertion, Saml2Constants.AssertionNamespace.OriginalString);
                    Saml2SecurityTokenHandler.WriteToken(xmlWriter, tokenWithoutEncryption);
                    xmlWriter.WriteEndElement();
                    WriteXmlAfterAssertion(xmlWriter);
                }

                return document;
            }

            return base.ToUnencryptedXml();
        }

        private void WriteXmlBeforeAssertion(XmlWriter xmlWriter)
        {
            xmlWriter.WriteStartElement(elementName, Saml2Constants.ProtocolNamespace.OriginalString);
            xmlWriter.WriteAttributeString(Saml2Constants.Message.IssueInstant, this.IssueInstant.ToString("o", CultureInfo.InvariantCulture));
            xmlWriter.WriteAttributeString(Saml2Constants.Message.Id, this.Id.Value);
            xmlWriter.WriteAttributeString(Saml2Constants.Message.Version, this.Version);

            xmlWriter.WriteStartElement(Saml2Constants.Message.Status);
            xmlWriter.WriteStartElement(Saml2Constants.Message.StatusCode);
            xmlWriter.WriteAttributeString(Saml2Constants.Message.Value, Saml2StatusCodeUtil.ToString(this.Status));
            xmlWriter.WriteEndElement();
            xmlWriter.WriteEndElement();
        }

        private static void WriteXmlAfterAssertion(XmlWriter xmlWriter)
        {
            xmlWriter.WriteEndElement();
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
        /// <param name="signatureAlgorithm">Sign with this signature algorithm.</param>
        /// <param name="digestAlgorithm">Hash with this digest algorithm.</param>
        /// <param name="encryptionCertificate">The certificate used for encrypting the assertion.</param>
        /// <returns></returns>
        public Saml2SecurityToken CreateSecurityToken(X509Certificate2 signingCertificate,
            int subjectConfirmationLifetime = 5,
            int issuedTokenLifetime = 60,
            string signatureAlgorithm = SecurityAlgorithms.RsaSha1Signature,
            string digestAlgorithm = SecurityAlgorithms.Sha1Digest,
            X509Certificate2 encryptionCertificate = null)
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

            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                TokenType = SamlTokenTypes.Saml2TokenProfile11.OriginalString,
                Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddMinutes(issuedTokenLifetime)),
                Subject = new ClaimsIdentity(this.ClaimsIdentity.Claims),
                AppliesToAddress = this.AppliesTo ?? this.Destination.Uri.OriginalString,
                TokenIssuerName = this.Issuer.Uri.OriginalString,
                SigningCredentials = new X509SigningCredentials(signingCertificate, signatureAlgorithm, digestAlgorithm),
                EncryptingCredentials = encryptionCertificate == null ? null : new EncryptedKeyEncryptingCredentials(encryptionCertificate)
            };

            Saml2SecurityToken = Saml2SecurityTokenHandler.CreateToken(tokenDescriptor) as Saml2SecurityToken;

            AddAuthenticationStatement();
            AddSubjectConfirmationData(subjectConfirmationLifetime);

            return Saml2SecurityToken;
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
            var authenticationStatement = new Saml2AuthenticationStatement(new Saml2AuthenticationContext(this.AuthenticationContextClassType));
            Saml2SecurityToken.Assertion.Statements.Add(authenticationStatement);
        }
    }
}
