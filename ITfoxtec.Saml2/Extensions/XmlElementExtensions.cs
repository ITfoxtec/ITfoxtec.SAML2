using System.Xml;

namespace ITfoxtec.Saml2.Extensions
{
    /// <summary>
    /// Extension methods for XmlElement
    /// </summary>
    internal static class XmlElementExtensions
    {
        public static string GetTextOrNull(this XmlElement xmlElement)
        {
            if (xmlElement == null || string.IsNullOrEmpty(xmlElement.InnerText))
            {
                return null;
            }
            return xmlElement.InnerText.Trim();
        }
    }
}
