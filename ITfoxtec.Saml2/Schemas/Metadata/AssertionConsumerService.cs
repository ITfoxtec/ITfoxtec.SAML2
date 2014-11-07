using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace ITfoxtec.Saml2.Schemas.Metadata
{
    /// <summary>
    /// Describe indexed endpoints that support the profiles of the
    /// Authentication Request protocol defined in [SAMLProf]. All service providers support at least one
    /// such endpoint, by definition.
    /// </summary>
    public class AssertionConsumerService
    {
        const string elementName = Saml2MetadataConstants.Message.AssertionConsumerService;

        /// <param name="binding">[Required]
        /// A required attribute that specifies the SAML binding supported by the endpoint. Each binding is
        /// assigned a URI to identify it.</param>
        /// <param name="location">[Required]
        /// A required URI attribute that specifies the location of the endpoint. The allowable syntax of this
        /// URI depends on the protocol binding.</param>
        public AssertionConsumerService(Uri binding, EndpointAddress location)
        {
            Binding = binding;
            Location = location;
        }

        /// <summary>
        /// [Required]
        /// A required attribute that specifies the SAML binding supported by the endpoint. Each binding is
        /// assigned a URI to identify it.
        /// </summary>
        public Uri Binding { get; protected set; }

        /// <summary>
        /// [Required]
        /// A required URI attribute that specifies the location of the endpoint. The allowable syntax of this
        /// URI depends on the protocol binding.
        /// </summary>
        public EndpointAddress Location { get; protected set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Saml2MetadataConstants.Message.Binding, Binding.OriginalString);
            yield return new XAttribute(Saml2MetadataConstants.Message.Location, Location.Uri.OriginalString);
            yield return new XAttribute(Saml2MetadataConstants.Message.Index, 0);
            yield return new XAttribute(Saml2MetadataConstants.Message.IsDefault, true);
        }
    }
}
