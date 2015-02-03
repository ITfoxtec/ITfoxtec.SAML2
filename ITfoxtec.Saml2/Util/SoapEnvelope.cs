using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace ITfoxtec.Saml2.Util
{
    public class SOAPEnvelope
    {
        public XmlDocument Body { get; set; }

        public XmlDocument ToSoapXml()
        {
            var envelope = new XElement(Constants.SoapEnvironmentNamespaceX + Constants.Envelope);

            envelope.Add(GetXContent());

            XmlDocument xmldoc = envelope.ToXmlDocument();
            return xmldoc;
        }

        public void FromSoapXml(string xml)
        {
            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xml);

            var bodyList = GetNodesByLocalname(xmlDoc.DocumentElement, "Body");
            if (bodyList.Count != 1)
            {
                throw new Exception("There is not exactly one Body element.");
            }
            xmlDoc.LoadXml(bodyList[0].InnerXml);
            Body = xmlDoc;
            var faultBody = GetNodeByLocalname(bodyList[0], "Fault");
            if (faultBody != null)
            {
                var faultcode = GetNodeByLocalname(faultBody, "faultcode");
                var faultstring = GetNodeByLocalname(faultBody, "faultstring");
                throw new Saml2ResponseException("Soap Error: " + faultcode + "\n" + faultstring);
            }
        }


        private XmlNodeList GetNodesByLocalname(XmlNode xe, string localName)
        {
            return xe.SelectNodes(string.Format("//*[local-name()='{0}']", localName));
        }

        private XmlNode GetNodeByLocalname(XmlNode xe, string localName)
        {
            return xe.SelectSingleNode(string.Format("//*[local-name()='{0}']", localName));
        }


        protected IEnumerable<XObject> GetXContent()
        {
            yield return new XAttribute(Constants.SoapEnvironmentNamespaceName, Constants.SoapEnvironmentNamespace.OriginalString);
            XDocument xBody = XDocument.Load(new XmlNodeReader(Body));
            var bodyElement = new XElement(Constants.SoapEnvironmentNamespaceX + Constants.Body, xBody.Root);
            yield return bodyElement;
        }

        private static class Constants
        {
            public static readonly Uri SoapEnvironmentNamespace = new Uri("http://schemas.xmlsoap.org/soap/envelope/");
            public static readonly XNamespace SoapEnvironmentNamespaceX = XNamespace.Get(SoapEnvironmentNamespace.OriginalString);
            public static readonly XName SoapEnvironmentNamespaceName = XNamespace.Xmlns + "SOAP-ENV";
            public const string Envelope = "Envelope";
            public const string Body = "Body";
        }
    }
}
