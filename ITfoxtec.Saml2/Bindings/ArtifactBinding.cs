using ITfoxtec.Saml2.Schemas;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace ITfoxtec.Saml2.Bindings
{
    public class ArtifactBinding : Saml2Binding
    {
        /// <summary>
        /// [Optional]
        /// Default EndCertOnly (Only the end certificate is included in the X.509 chain information).
        /// </summary>
        public X509IncludeOption CertificateIncludeOption { get; set; }

        /// <summary>
        /// Html post content.
        /// </summary>
        public string SAMLart { get; set; }

        public ArtifactBinding()
        {
            CertificateIncludeOption = X509IncludeOption.EndCertOnly;
        }


        public Saml2Request Unbind(HttpRequestBase request, ArtifactResolve saml2Request, X509Certificate2 signatureValidationCertificate)
        {
            return UnbindInternal(request, saml2Request, Saml2Constants.Message.SamlArt, signatureValidationCertificate);
        }

        protected Saml2Request UnbindInternal(HttpRequestBase request, ArtifactResolve saml2RequestResponse, string messageName, X509Certificate2 signatureValidationCertificate)
        {
            base.UnbindInternal(request, saml2RequestResponse, signatureValidationCertificate);

            if (!"GET".Equals(request.HttpMethod, StringComparison.InvariantCultureIgnoreCase))
                throw new InvalidSaml2BindingException("Not HTTP POST Method.");

            if (!request.QueryString.AllKeys.Contains(messageName))
                throw new Saml2BindingException("QueryString does not contain " + messageName);

            if (request.QueryString.AllKeys.Contains(Saml2Constants.Message.RelayState))
            {
                RelayState = request.QueryString[Saml2Constants.Message.RelayState];
            }

            saml2RequestResponse.Artifact = request.QueryString[messageName];

            return saml2RequestResponse;
        }
    }
}
