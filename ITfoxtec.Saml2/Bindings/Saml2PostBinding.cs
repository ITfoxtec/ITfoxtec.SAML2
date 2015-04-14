using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Xml;
using ITfoxtec.Saml2.Schemas;
using System.ServiceModel;

namespace ITfoxtec.Saml2.Bindings
{
    public class Saml2PostBinding : Saml2Binding
    {
        /// <summary>
        /// [Optional]
        /// Default EndCertOnly (Only the end certificate is included in the X.509 chain information).
        /// </summary>
        public X509IncludeOption CertificateIncludeOption { get; set; }

        /// <summary>
        /// Html post content.
        /// </summary>
        public string PostContent { get; set; }

        public Saml2PostBinding()
        {
            CertificateIncludeOption = X509IncludeOption.EndCertOnly;
        }

        public Saml2PostBinding Bind(Saml2Request saml2Request, X509Certificate2 signingCertificate = null, string signatureMethod = SecurityAlgorithms.RsaSha1Signature, string digestMethod = SecurityAlgorithms.Sha1Digest)
        {
            return BindInternal(saml2Request, Saml2Constants.Message.SamlRequest, signingCertificate, signatureMethod, digestMethod);
        }

        public Saml2PostBinding Bind(Saml2Response saml2Response, X509Certificate2 signingCertificate = null, string signatureMethod = SecurityAlgorithms.RsaSha1Signature, string digestMethod = SecurityAlgorithms.Sha1Digest)
        {
            return BindInternal(saml2Response as Saml2Request, Saml2Constants.Message.SamlResponse, signingCertificate, signatureMethod, digestMethod);
        }

        protected Saml2PostBinding BindInternal(Saml2Request saml2RequestResponse, string messageName, X509Certificate2 signingCertificate, string signatureMethod, string digestMethod)
        {
            base.BindInternal(saml2RequestResponse, signingCertificate);

            if (signingCertificate != null)
            {
                XmlDocument = XmlDocument.SignDocument(signingCertificate, CertificateIncludeOption, saml2RequestResponse.Id.Value, signatureMethod, digestMethod, saml2RequestResponse.ToUnencryptedXml());
            }

            PostContent = string.Concat(HtmlPostPage(saml2RequestResponse.Destination, messageName));
            return this;
        }

        private IEnumerable<string> HtmlPostPage(EndpointAddress destination, string messageName)
        {
            yield return string.Format(
@"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""utf-8"" />
    <meta http-equiv=""X-UA-Compatible"" content=""IE=edge"">
    <meta name=""viewport"" content=""initial-scale=1.0, width=device-width"" />
    <title>Single sign on</title>
</head>
<body onload=""document.forms[0].submit()"">
    <noscript>
        <p>
            <strong>Note:</strong> Since your browser does not support JavaScript, 
            you must press the Continue button once to proceed.
        </p>
    </noscript>
    <form action=""{0}"" method=""post"">
        <div>", destination);

            yield return string.Format(
@"<input type=""hidden"" name=""{0}"" value=""{1}""/>", messageName, Convert.ToBase64String(Encoding.UTF8.GetBytes(XmlDocument.OuterXml)));

            if (!string.IsNullOrWhiteSpace(RelayState))
            {
                yield return string.Format(
@"<input type=""hidden"" name=""{0}"" value=""{1}""/>", Saml2Constants.Message.RelayState, RelayState);
            }

            yield return
@"</div>
        <noscript>
            <div>
                <input type=""submit"" value=""Continue""/>
            </div>
        </noscript>
    </form>
</body>
</html>";
        }

        public Saml2Response Unbind(HttpRequestBase request, Saml2Response saml2Response, X509Certificate2 signatureValidationCertificate)
        {
            return UnbindInternal(request, saml2Response as Saml2Request, Saml2Constants.Message.SamlResponse, signatureValidationCertificate) as Saml2Response;
        }

        public Saml2Request Unbind(HttpRequestBase request, Saml2Request saml2Request, X509Certificate2 signatureValidationCertificate)
        {
            return UnbindInternal(request, saml2Request, Saml2Constants.Message.SamlRequest, signatureValidationCertificate);
        }

        protected Saml2Request UnbindInternal(HttpRequestBase request, Saml2Request saml2RequestResponse, string messageName, X509Certificate2 signatureValidationCertificate)
        {
            base.UnbindInternal(request, saml2RequestResponse, signatureValidationCertificate);

            if (!"POST".Equals(request.HttpMethod, StringComparison.InvariantCultureIgnoreCase))
                throw new InvalidSaml2BindingException("Not HTTP POST Method.");

            if (!request.Form.AllKeys.Contains(messageName))
                throw new Saml2BindingException("HTTP Form does not contain " + messageName);

            if (request.Form.AllKeys.Contains(Saml2Constants.Message.RelayState))
            {
                RelayState = request.Form[Saml2Constants.Message.RelayState];
            }

            saml2RequestResponse.Read(Encoding.UTF8.GetString(Convert.FromBase64String(request.Form[messageName])), true);
            XmlDocument = saml2RequestResponse.XmlDocument;
            return saml2RequestResponse;
        }
    }
}
