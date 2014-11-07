using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Saml2.Schemas.Metadata
{
    /// <summary>
    /// The EntitiesDescriptor element contains the metadata for an optionally named group of SAML entities.
    /// </summary>
    public class EntityDescriptor
    {
        const string elementName = Saml2MetadataConstants.Message.EntityDescriptor;

        /// <param name="entityId">[Required] Specifies the unique identifier of the SAML entity whose metadata is described by the element's contents.</param>
        /// <param name="metadataSigningCertificate">An metadata XML signature that authenticates the containing element and its contents.</param>
        public EntityDescriptor(EndpointReference entityId, X509Certificate2 metadataSigningCertificate = null)
        {
            EntityId = entityId;
            Id = new Saml2Id();
            MetadataSigningCertificate = metadataSigningCertificate;
            CertificateIncludeOption = X509IncludeOption.EndCertOnly;
        }

        /// <summary>
        /// Specifies the unique identifier of the SAML entity whose metadata is described by the element's contents.
        /// </summary>
        public EndpointReference EntityId { get; protected set; }

        /// <summary>
        /// A document-unique identifier for the element, typically used as a reference point when signing.
        /// </summary>
        public Saml2Id Id { get; protected set; }

        /// <summary>
        /// [Optional]
        /// An metadata XML signature that authenticates the containing element and its contents.
        /// </summary>
        public X509Certificate2 MetadataSigningCertificate { get; protected set; }

        /// <summary>
        /// [Optional]
        /// Default EndCertOnly (Only the end certificate is included in the X.509 chain information).
        /// </summary>
        public X509IncludeOption CertificateIncludeOption { get; set; }

        /// <summary>
        /// [Optional]
        /// Optional attribute indicates the expiration time of the metadata contained in the element and any contained elements.
        /// 
        /// Metadata is valid until in days from now.
        /// </summary>
        public int? ValidUntil { get; set; }

        /// <summary>
        /// [Required]
        /// The SPSSODescriptor element extends SSODescriptorType with content reflecting profiles specific
        /// to service providers. 
        /// </summary>
        public SPSsoDescriptor SPSsoDescriptor  { get; set; }

        /// <summary>
        /// [Optional]
        /// Optional element identifying various kinds of contact personnel.
        /// </summary>
        public ContactPerson ContactPerson { get; set; }

        public XmlDocument ToXmlDocument()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());
            var xmlDocument = envelope.ToXmlDocument();
            if(MetadataSigningCertificate != null)
            {
                xmlDocument.SignDocument(MetadataSigningCertificate, CertificateIncludeOption, Id.Value);
            }
            return xmlDocument;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2MetadataConstants.Message.EntityId, EntityId.Uri.OriginalString);
            yield return new XAttribute(Saml2MetadataConstants.Message.Id, Id);
            if (ValidUntil.HasValue)
            {
                yield return new XAttribute(Saml2MetadataConstants.Message.ValidUntil, DateTime.UtcNow.AddDays(ValidUntil.Value).ToString("o", CultureInfo.InvariantCulture));
            }
            yield return new XAttribute(Saml2MetadataConstants.MetadataNamespaceNameX, Saml2MetadataConstants.MetadataNamespace);

            if (SPSsoDescriptor == null)
            {
                throw new ArgumentNullException("SPSsoDescriptor property");
            }

            yield return SPSsoDescriptor.ToXElement();

            if (ContactPerson != null)
            {
                yield return ContactPerson.ToXElement();
            }
        }



    }
}
