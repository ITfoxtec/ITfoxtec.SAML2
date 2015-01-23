using System;
using System.Xml.Linq;

namespace ITfoxtec.Saml2.Schemas
{
    public static class Saml2Constants
    {
        /// <summary>
        /// SAML Version Number.
        /// </summary>
        public const string VersionNumber = "2.0";

        /// <summary>
        /// Saml2 Bearer token.
        /// </summary>
        public static Uri Saml2BearerToken = new Uri("urn:oasis:names:tc:SAML:2.0:cm:bearer");

        /// <summary>
        /// The XML namespace of the SAML2 Assertion.
        /// </summary>
        public static Uri AssertionNamespace = new Uri("urn:oasis:names:tc:SAML:2.0:assertion");
        /// <summary>
        /// The XML namespace of the SAML2 Assertion.
        /// </summary>
        public static XNamespace AssertionNamespaceX = XNamespace.Get( AssertionNamespace.OriginalString );
        /// <summary>
        /// The XML Namespace Name of the SAML2 Assertion.
        /// </summary>
        public static XName AssertionNamespaceNameX = XNamespace.Xmlns + "saml2";

        /// <summary>
        /// The XML namespace of the SAML2 Protocol.
        /// </summary>
        public static Uri ProtocolNamespace = new Uri("urn:oasis:names:tc:SAML:2.0:protocol");
        /// <summary>
        /// The XML namespace of the SAML2 Protocol.
        /// </summary>
        public static XNamespace ProtocolNamespaceX = XNamespace.Get( ProtocolNamespace.OriginalString );
        /// <summary>
        /// The XML Namespace Name of the SAML2 Protocol.
        /// </summary>
        public static XName ProtocolNamespaceNameX = XNamespace.Xmlns + "saml2p";

        public static class Message
        {
            public const string SamlResponse = "SAMLResponse";

            public const string SamlRequest = "SAMLRequest";

            public const string RelayState = "RelayState";

            public const string Assertion = "Assertion";

            public const string Protocol = "Protocol";

            public const string AuthnRequest = "AuthnRequest";

            public const string AuthnResponse = "Response";

            public const string LogoutRequest = "LogoutRequest";

            public const string LogoutResponse = "LogoutResponse";

            public const string Id = "ID";

            public const string Version = "Version";

            public const string IssueInstant = "IssueInstant";

            public const string Consent = "Consent";

            public const string Destination = "Destination";

            public const string Signature = "Signature";

            public const string SigAlg = "SigAlg";

            public const string Issuer = "Issuer";

            public const string Status = "Status";

            public const string StatusCode = "StatusCode";

            public const string Value = "Value";

            public const string AssertionConsumerServiceURL = "AssertionConsumerServiceURL";

            public const string RequestedAuthnContext = "RequestedAuthnContext";

            public const string Comparison = "Comparison";

            public const string AuthnContextClassRef = "AuthnContextClassRef";

            public const string ForceAuthn = "ForceAuthn";

            public const string IsPassive = "IsPassive";

            public const string NameId = "NameID";

            public const string SessionIndex = "SessionIndex";

            public const string Format = "Format";

            public const string NotOnOrAfter = "NotOnOrAfter";

            public const string Reason = "Reason";

            public const string NameIdPolicy = "NameIDPolicy";

            public const string AllowCreate = "AllowCreate";

            public const string SpNameQualifier = "SPNameQualifier";

            public const string InResponseTo = "InResponseTo";

            public const string Conditions = "Conditions";
            
            public const string AudienceRestriction = "AudienceRestriction";

            public const string Audience = "Audience";

            public const string Subject = "Subject";

            public const string SubjectConfirmation = "SubjectConfirmation";
            
            public const string SubjectConfirmationData = "SubjectConfirmationData";
        }
    
    }
}
