using ITfoxtec.Saml2.Claims;
using ITfoxtec.Saml2.Schemas;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Saml2
{
    /// <summary>
    /// Saml2 Logout Request.
    /// </summary>
    public class Saml2LogoutRequest : Saml2Request
    {
        const string elementName = Saml2Constants.Message.LogoutRequest;

        /// <summary>
        /// [Optional]
        /// The time at which the request expires, after which the recipient may discard the message. The time
        /// value is encoded in UTC, as described in Section 1.3.3.
        /// </summary>
        public DateTime? NotOnOrAfter { get; set; }

        /// <summary>
        /// [Optional]
        /// An indication of the reason for the logout, in the form of a URI reference.
        /// </summary>
        public Uri Reason { get; set; }        

        /// <summary>
        /// [Required]
        /// The identifier and associated attributes (in plaintext or encrypted form) that specify the principal as
        /// currently recognized by the identity and service providers prior to this request. (For more information
        /// on this element, see Section 2.2.)
        /// </summary>
        public Saml2NameIdentifier NameId { get; private set; }

        /// <summary>
        /// [Optional]
        /// The identifier that indexes this session at the message recipient.
        /// </summary>
        public string SessionIndex { get; private set; }

        public Saml2LogoutRequest()
        {
            NotOnOrAfter = DateTime.UtcNow.AddMinutes(10);

            var identity = ClaimsPrincipal.Current.Identities.First();
            if (identity.IsAuthenticated)
            {
                NameId = new Saml2NameIdentifier(ReadClaimValue(identity, Saml2ClaimTypes.NameId), new Uri(ReadClaimValue(identity, Saml2ClaimTypes.NameIdFormat)));
                SessionIndex = ReadClaimValue(identity, Saml2ClaimTypes.SessionIndex);
            }           
        }
		
        public Saml2LogoutRequest( string nameId, string nameIdFormat, string sessionIndex )
        {
            NotOnOrAfter = DateTime.UtcNow.AddMinutes( 10 );

            NameId = new Saml2NameIdentifier( nameId, new Uri( nameIdFormat ) );
            SessionIndex = sessionIndex;
        }

        private static string ReadClaimValue(ClaimsIdentity identity, string claimType)
        {
            var claim = identity.Claims.FirstOrDefault(c => c.Type == claimType);
            if (claim == null)
            {
                throw new InvalidOperationException("Missing Claim Type: " + claimType);
            }
            return claim.Value;
        }

        public override XmlDocument ToXml()
        {
            var envelope = new XElement(Saml2Constants.ProtocolNamespaceX + elementName);

            envelope.Add(base.GetXContent());
            envelope.Add(GetXContent());

            XmlDocument = envelope.ToXmlDocument();
            return XmlDocument;
        }

        protected override IEnumerable<XObject> GetXContent()
        {
            if (NotOnOrAfter.HasValue)
            {
                yield return new XAttribute(Saml2Constants.Message.NotOnOrAfter, NotOnOrAfter.Value.ToString("o", CultureInfo.InvariantCulture));
            }

            if (Reason != null)
            {
                yield return new XAttribute(Saml2Constants.Message.Reason, Reason.OriginalString);
            }

            if (NameId != null)
            {
                yield return new XElement(Saml2Constants.AssertionNamespaceX + Saml2Constants.Message.NameId, NameId.Value, new XAttribute(Saml2Constants.Message.Format, NameId.Format));
            }

            if (SessionIndex != null)
            {
                yield return new XElement(Saml2Constants.ProtocolNamespaceX + Saml2Constants.Message.SessionIndex, SessionIndex);
            }
        }

        protected override void ValidateElementName()
        {
            if (XmlDocument.DocumentElement.LocalName != elementName)
            {
                throw new Saml2ResponseException("Not a SAML2 Logout Request.");
            }
        }
    }
}
