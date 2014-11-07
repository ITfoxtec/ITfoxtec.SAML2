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
    /// Elements of type EndpointType that describe endpoints that support the Single Logout profiles defined in [SAMLProf].
    /// 
    /// The complex type EndpointType describes a SAML protocol binding endpoint at which a SAML entity can
    /// be sent protocol messages. Various protocol or profile-specific metadata elements are bound to this type.
    /// </summary>
    public class SingleLogoutService
    {
        const string elementName = Saml2MetadataConstants.Message.SingleLogoutService;

        /// <param name="binding">[Required]
        /// A required attribute that specifies the SAML binding supported by the endpoint. Each binding is
        /// assigned a URI to identify it.</param>
        /// <param name="location">[Required]
        /// A required URI attribute that specifies the location of the endpoint. The allowable syntax of this
        /// URI depends on the protocol binding.</param>
        public SingleLogoutService(Uri binding, EndpointAddress location) : this(binding, location, location)
        { }

        /// <param name="binding">[Required]
        /// A required attribute that specifies the SAML binding supported by the endpoint. Each binding is
        /// assigned a URI to identify it.</param>
        /// <param name="location">[Required]
        /// A required URI attribute that specifies the location of the endpoint. The allowable syntax of this
        /// URI depends on the protocol binding.</param>
        /// <param name="responseLocation">[Optional]
        /// Optionally specifies a different location to which response messages sent as part of the protocol
        /// or profile should be sent. The allowable syntax of this URI depends on the protocol binding.</param>
        public SingleLogoutService(Uri binding, EndpointAddress location, EndpointAddress responseLocation)
        {
            Binding = binding;
            Location = location;
            ResponseLocation = responseLocation;
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

        /// <summary>
        /// [Optional]
        /// Optionally specifies a different location to which response messages sent as part of the protocol
        /// or profile should be sent. The allowable syntax of this URI depends on the protocol binding.
        /// </summary>
        public EndpointAddress ResponseLocation { get; protected set; }

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
            yield return new XAttribute(Saml2MetadataConstants.Message.ResponseLocation, ResponseLocation);
        }
    }
}
