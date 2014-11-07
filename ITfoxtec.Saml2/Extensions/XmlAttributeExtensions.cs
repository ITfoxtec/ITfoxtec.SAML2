using System.Xml;

namespace ITfoxtec.Saml2.Extensions
{
    /// <summary>
    /// Extension methods for XmlAttribute
    /// </summary>
    internal static class XmlAttributeExtensions
    {
        public static string GetValueOrNull(this XmlAttribute xmlAttribute)
        {
            if (xmlAttribute == null)
            {
                return null;
            }
            return xmlAttribute.Value;
        }
    }
}
