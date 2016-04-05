using System.Xml;

namespace ITfoxtec.Saml2
{
    /// <summary>
    /// Extension methods for string
    /// </summary>
    internal static class StringExtensions
    {
        /// <summary>
        /// Converts an string to an XmlDocument.
        /// </summary>
        internal static XmlDocument ToXmlDocument(this string xml)
        {
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.XmlResolver = null;
            xmlDocument.PreserveWhitespace = true;
            xmlDocument.LoadXml(xml);
            return xmlDocument;
        }
    }
}
