using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace ITfoxtec.Saml2.Schemas.Metadata
{
    /// <summary>
    /// Language-qualified name for the service.
    /// </summary>
    public class ServiceName
    {
        const string elementName = Saml2MetadataConstants.Message.ServiceName;

        /// <param name="name">Name for the service.</param>
        /// <param name="lang">Language.</param>
        public ServiceName(string name, string lang)
        {
            Name = name;
            Lang = lang;
        }

        /// <summary>
        /// Language.
        /// </summary>
        public string Lang { get; protected set; }

        /// <summary>
        /// Name for the service.
        /// </summary>
        public string Name { get; protected set; }

        public XElement ToXElement()
        {
            var envelope = new XElement(Saml2MetadataConstants.MetadataNamespaceX + elementName);

            envelope.Add(GetXContent());

            return envelope;
        }

        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(XNamespace.Xml + Saml2MetadataConstants.Message.Lang, Lang);

            yield return new XText(Name);
        }
    }
}
