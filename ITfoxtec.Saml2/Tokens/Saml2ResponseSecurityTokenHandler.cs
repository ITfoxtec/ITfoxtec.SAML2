using ITfoxtec.Saml2.Claims;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Xml;

namespace ITfoxtec.Saml2.Tokens
{
    public class Saml2ResponseSecurityTokenHandler : Saml2SecurityTokenHandler
    {
        public static Saml2ResponseSecurityTokenHandler GetSaml2SecurityTokenHandler()
        {
            var handler = new Saml2ResponseSecurityTokenHandler();
            var identityConfiguration = FederatedAuthentication.FederationConfiguration.IdentityConfiguration;
            handler.Configuration = new SecurityTokenHandlerConfiguration
            {
                SaveBootstrapContext = identityConfiguration.SaveBootstrapContext,
                AudienceRestriction = identityConfiguration.AudienceRestriction,
                IssuerNameRegistry = new Saml2ResponseIssuerNameRegistry(),
                CertificateValidationMode = identityConfiguration.CertificateValidationMode,
                RevocationMode = identityConfiguration.RevocationMode,
                CertificateValidator = identityConfiguration.CertificateValidator,
                DetectReplayedTokens = identityConfiguration.DetectReplayedTokens,
            };

            handler.SamlSecurityTokenRequirement.NameClaimType = ClaimTypes.NameIdentifier;
            return handler;
        }

        public override ReadOnlyCollection<ClaimsIdentity> ValidateToken(SecurityToken token)
        {
            var saml2SecurityToken = token as Saml2SecurityToken;

            this.ValidateConditions(saml2SecurityToken.Assertion.Conditions, SamlSecurityTokenRequirement.ShouldEnforceAudienceRestriction(Configuration.AudienceRestriction.AudienceMode, saml2SecurityToken));

            if (this.Configuration.DetectReplayedTokens)
            {
                this.DetectReplayedToken(saml2SecurityToken);
            }

            // If the backing token is x509, validate trust
            X509SecurityToken issuerToken = saml2SecurityToken.IssuerToken as X509SecurityToken;
            if (issuerToken != null)
            {
                this.CertificateValidator.Validate(issuerToken.Certificate);
            }

            var identity = this.CreateClaims(saml2SecurityToken);
            if (saml2SecurityToken.Assertion.Subject.NameId == null)
            {
                throw new InvalidDataException("The requered NameID Assertion is null");
            }
            identity.AddClaim(new Claim(Saml2ClaimTypes.NameId, saml2SecurityToken.Assertion.Subject.NameId.Value));
            if (saml2SecurityToken.Assertion.Subject.NameId.Format == null)
            {
                throw new InvalidDataException("The requered NameID Assertion Format is null");
            }
            identity.AddClaim(new Claim(Saml2ClaimTypes.NameIdFormat, saml2SecurityToken.Assertion.Subject.NameId.Format.AbsoluteUri));
            identity.AddClaim(new Claim(Saml2ClaimTypes.SessionIndex, saml2SecurityToken.Id));

            if (Configuration.SaveBootstrapContext)
            {
                identity.BootstrapContext = new BootstrapContext(saml2SecurityToken, this);
            }            

            return new List<ClaimsIdentity>(1) { identity }.AsReadOnly();
        }

        public override string WriteToken(SecurityToken token)
        {
            var builder = new StringBuilder();
            using (var writer = XmlWriter.Create(builder))
            {
                WriteToken(writer, token);
            }
            return builder.ToString();
        }
    }
}
