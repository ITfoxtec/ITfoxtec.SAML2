using ITfoxtec.Saml2.Cryptography;
using ITfoxtec.Saml2.Schemas;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Saml2
{
    /// <summary>
    /// Extension methods for XmlDocument
    /// </summary>
    internal static class XmlDocumentExtensions
    {
        /// <summary>
        /// Signs an XmlDocument with an xml signature using the signing certificate given as argument to the method.
        /// </summary>
        /// <param name="certificate">The certificate used to sign the document</param>
        /// <param name="includeOption">Certificate include option</param>
        /// <param name="id">The is of the topmost element in the xmldocument</param>
        internal static XmlDocument SignDocument(this XmlDocument xmlDocument, X509Certificate2 certificate, X509IncludeOption includeOption, string id)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException("certificate");
            }
 
            var signedXml = new Saml2SignedXml(xmlDocument);
            signedXml.ComputeSignature(certificate, includeOption, id);

            var issuer = xmlDocument.DocumentElement[Saml2Constants.Message.Issuer, Saml2Constants.AssertionNamespace.OriginalString];
            xmlDocument.DocumentElement.InsertAfter(xmlDocument.ImportNode(signedXml.GetXml(), true), issuer);
            return xmlDocument;
        }


        /// <summary>
        /// Converts an XmlDocument to an XDocument.
        /// </summary>
        internal static XDocument ToXDocument(this XmlDocument xmlDocument)
        {
            using (var reader = xmlDocument.CreateNavigator().ReadSubtree())
            {
                return XDocument.Load(reader);
            }
        }

        /// <summary>
        /// Converts an XmlDocument to an XElement.
        /// </summary>
        internal static XElement ToXElement(this XmlDocument xmlDocument)
        {
            using (var reader = xmlDocument.CreateNavigator().ReadSubtree())
            {
                return XElement.Load(reader);
            }
        }
    }
}