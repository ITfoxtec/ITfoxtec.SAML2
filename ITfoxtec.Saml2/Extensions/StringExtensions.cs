﻿using System.IO;
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
            using (var stringReader = new StringReader(xml))
            using (var xmlReader = XmlReader.Create(stringReader, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }))
            {
                XmlDocument xmlDocument = new XmlDocument();
                xmlDocument.XmlResolver = null;
                xmlDocument.PreserveWhitespace = true;
                xmlDocument.Load(xmlReader);
                return xmlDocument;
            }
        }
    }
}
