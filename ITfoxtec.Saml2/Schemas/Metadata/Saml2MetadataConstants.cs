using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace ITfoxtec.Saml2.Schemas.Metadata
{
    internal class Saml2MetadataConstants
    {
        /// <summary>
        /// The XML namespace of the Metadata.
        /// </summary>
        public const string MetadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata";
        /// <summary>
        /// The XML namespace of the Metadata.
        /// </summary>
        public static readonly XNamespace MetadataNamespaceX = XNamespace.Get(MetadataNamespace);

        /// <summary>
        /// The XML Namespace Name of the Metadata.
        /// </summary>
        public static readonly XName MetadataNamespaceNameX = XNamespace.Xmlns + "m";     

        public const string AttributeNameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

        public class Message
        {
            public const string EntityDescriptor = "EntityDescriptor";

            public const string SPSsoDescriptor = "SPSSODescriptor";

            public const string ContactPerson = "ContactPerson";

            public const string EntityId = "entityID";
            
            public const string Id = "ID";

            public const string ValidUntil = "validUntil";
            
            public const string ContactType = "contactType";

            public const string Company = "Company";

            public const string GivenName = "GivenName";

            public const string SurName = "SurName";

            public const string EmailAddress = "EmailAddress";

            public const string TelephoneNumber = "TelephoneNumber";

            public const string KeyDescriptor = "KeyDescriptor";

            public const string Use = "use";

            public const string SingleLogoutService = "SingleLogoutService";

            public const string Binding = "Binding";

            public const string Location = "Location";

            public const string ResponseLocation = "ResponseLocation";

            public const string ProtocolSupportEnumeration = "protocolSupportEnumeration";
            
            public const string AuthnRequestsSigned = "AuthnRequestsSigned";

            public const string WantAssertionsSigned = "WantAssertionsSigned";

            public const string NameIDFormat = "NameIDFormat";

            public const string AssertionConsumerService = "AssertionConsumerService";

            public const string Index = "index";

            public const string IsDefault = "isDefault";

            public const string AttributeConsumingService = "AttributeConsumingService";

            public const string ServiceName = "ServiceName";

            public const string Lang = "lang";

            public const string RequestedAttribute = "RequestedAttribute";

            public const string Name = "Name";

            public const string NameFormat = "NameFormat";

            public const string IsRequired = "isRequired";

        }
        
    }
}
