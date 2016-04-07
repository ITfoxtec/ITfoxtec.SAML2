using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Saml2
{
    /// <summary>
    /// Extension methods for XElement
    /// </summary>
    internal static class XElementExtensions
    {
        internal static XmlDocument ToXmlDocument(this XElement xElement)
        {
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.XmlResolver = null;
            xmlDocument.PreserveWhitespace = true;
            using (var reader = xElement.CreateReader())
            {
                reader.Settings.XmlResolver = null;
                xmlDocument.Load(reader);
            }
            return xmlDocument;
        }
    }
}
