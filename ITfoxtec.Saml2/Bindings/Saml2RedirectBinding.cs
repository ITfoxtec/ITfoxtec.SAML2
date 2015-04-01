using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Web;
using System.Xml;
using ITfoxtec.Saml2.Schemas;
using ITfoxtec.Saml2.Cryptography;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Saml2.Util;
using Security.Cryptography;
using Security.Cryptography.X509Certificates;

namespace ITfoxtec.Saml2.Bindings
{
    public class Saml2RedirectBinding : Saml2Binding
    {
        public Uri RedirectLocation { get; protected set; }

        public string Signature { get; protected set; }
        public string SignatureAlgorithm { get; protected set; }

        /// <summary>
        ///   Computes the RedirectLocation and Signature for the request.
        /// </summary>
        /// <param name="saml2Request">The SAML2 request.</param>
        /// <param name="signingCertificate">Certificate to sign the request.</param>
        /// <param name="signatureAlgorithm">
        ///   Algorithm to sign the request.
        ///   <example>http://www.w3.org/2000/09/xmldsig#rsa-sha1</example>
        ///   <example>http://www.w3.org/2001/04/xmldsig-more#rsa-sha256</example>
        /// </param>
        /// <returns></returns>
        public Saml2RedirectBinding Bind(Saml2Request saml2Request, X509Certificate2 signingCertificate = null, string signatureAlgorithm = null)
        {
            return BindInternal(saml2Request, Saml2Constants.Message.SamlRequest, signingCertificate, signatureAlgorithm);
        }

        /// <summary>
        ///   Computes the RedirectLocation and Signature for the response.
        /// </summary>
        /// <param name="saml2Response">The SAML2 response.</param>
        /// <param name="signingCertificate">Certificate to sign the response.</param>
        /// <param name="signatureAlgorithm">
        ///   Algorithm to sign the response.
        ///   <example>http://www.w3.org/2000/09/xmldsig#rsa-sha1</example>
        ///   <example>http://www.w3.org/2001/04/xmldsig-more#rsa-sha256</example>
        /// </param>
        /// <returns></returns>
        public Saml2RedirectBinding Bind(Saml2Response saml2Response, X509Certificate2 signingCertificate = null, string signatureAlgorithm = null)
        {
            return BindInternal(saml2Response as Saml2Request, Saml2Constants.Message.SamlResponse, signingCertificate, signatureAlgorithm);
        }

        protected Saml2RedirectBinding BindInternal(Saml2Request saml2RequestResponse, string messageName, X509Certificate2 signingCertificate, string signatureAlgorithm = null)
        {
            base.BindInternal(saml2RequestResponse, signingCertificate);

            var requestQueryString = string.Join("&", RequestQueryString(signingCertificate, messageName, signatureAlgorithm));
            if (signingCertificate != null)
            {
                requestQueryString = this.SignQueryString(requestQueryString, signingCertificate, signatureAlgorithm);
            }

            RedirectLocation = new Uri(string.Join("?", saml2RequestResponse.Destination.Uri.OriginalString, requestQueryString));

            return this;
        }

        private string SignQueryString(string queryString, X509Certificate2 signingCertificate, string signatureAlgorithm = null)
        {
            if (signingCertificate.HasCngKey())
            {
                CngKey key = signingCertificate.GetCngPrivateKey();
                using (RSACng rsa = new RSACng(key))
                {
                    if (signatureAlgorithm == null)
                    {
                        signatureAlgorithm = SecurityAlgorithms.RsaSha1Signature;
                    }

                    switch (signatureAlgorithm)
                    {
                        case SecurityAlgorithms.RsaSha1Signature:
                            rsa.SignatureHashAlgorithm = CngAlgorithm.Sha1;
                            break;

                        case SecurityAlgorithms.RsaSha256Signature:
                            rsa.SignatureHashAlgorithm = CngAlgorithm.Sha256;
                            break;

                        default:
                            throw new NotSupportedException("Only SHA1 and SHA256 is supported.");
                    }

                    Saml2Sign saml2Signed = new Saml2Sign(rsa);
                    SignatureAlgorithm = signatureAlgorithm;
                    Signature = Convert.ToBase64String(saml2Signed.SignData(Encoding.UTF8.GetBytes(queryString)));
                }
            }
            else
            {
                Saml2Sign saml2Signed = new Saml2Sign(signingCertificate.PrivateKey);
                SignatureAlgorithm = signatureAlgorithm ?? signingCertificate.PrivateKey.SignatureAlgorithm;
                Signature = Convert.ToBase64String(saml2Signed.SignData(Encoding.UTF8.GetBytes(queryString)));
            }

            return string.Join("&", queryString, string.Join("=", Saml2Constants.Message.Signature, HttpUtility.UrlEncode(Signature)));
        }

        private IEnumerable<string> RequestQueryString(X509Certificate2 signingCertificate, string messageName, string signatureAlgorithm)
        {
            yield return string.Join("=", messageName, HttpUtility.UrlEncode(CompressRequest()));

            if (!string.IsNullOrWhiteSpace(RelayState))
            {
                yield return string.Join("=", Saml2Constants.Message.RelayState, HttpUtility.UrlEncode(RelayState));
            }

            if (signingCertificate != null)
            {
                if (signingCertificate.HasCngKey())
                {
                    if (signingCertificate.GetCngPrivateKey().Algorithm.Algorithm == "RSA")
                    {
                        signatureAlgorithm = signatureAlgorithm ?? SecurityAlgorithms.RsaSha1Signature;
                        yield return string.Join("=", Saml2Constants.Message.SigAlg, HttpUtility.UrlEncode(signatureAlgorithm));
                    }
                }
                else
                {
                    yield return string.Join("=", Saml2Constants.Message.SigAlg, HttpUtility.UrlEncode(signingCertificate.PrivateKey.SignatureAlgorithm));
                }
            }
        }

        private string CompressRequest()
        {
            using (var compressedStream = new MemoryStream())
            using (var deflateStream = new DeflateStream(compressedStream, CompressionLevel.Optimal))
            {
                using (var originalStream = new StreamWriter(deflateStream))
                {
                    originalStream.Write(XmlDocument.OuterXml);
                }

                return Convert.ToBase64String(compressedStream.GetBuffer());
            }
        }

        public Saml2Response Unbind(HttpRequestBase request, Saml2Request saml2Request, X509Certificate2 signatureValidationCertificate)
        {
            return UnbindInternal(request, saml2Request as Saml2Request, Saml2Constants.Message.SamlRequest, signatureValidationCertificate) as Saml2Response;
        }

        public Saml2Response Unbind(HttpRequestBase request, Saml2Response saml2Response, X509Certificate2 signatureValidationCertificate)
        {
            return UnbindInternal(request, saml2Response as Saml2Request, Saml2Constants.Message.SamlResponse, signatureValidationCertificate) as Saml2Response;
        }

        protected Saml2Request UnbindInternal(HttpRequestBase request, Saml2Request saml2RequestResponse, string messageName, X509Certificate2 signatureValidationCertificate)
        {
            base.UnbindInternal(request, saml2RequestResponse, signatureValidationCertificate);

            if (!"GET".Equals(request.HttpMethod, StringComparison.InvariantCultureIgnoreCase))
                throw new InvalidSaml2BindingException("Not HTTP GET Method.");

            if (!request.QueryString.AllKeys.Contains(messageName))
                throw new Saml2BindingException("HTTP Query String does not contain " + messageName);

            if (!request.QueryString.AllKeys.Contains(Saml2Constants.Message.Signature))
                throw new Saml2BindingException("HTTP Query String does not contain " + Saml2Constants.Message.Signature);

            if (!request.QueryString.AllKeys.Contains(Saml2Constants.Message.SigAlg))
                throw new Saml2BindingException("HTTP Query String does not contain " + Saml2Constants.Message.SigAlg);

            if (request.QueryString.AllKeys.Contains(Saml2Constants.Message.RelayState))
            {
                RelayState = request.QueryString[Saml2Constants.Message.RelayState];
            }

            SignatureAlgorithm = request.QueryString[Saml2Constants.Message.SigAlg];
            ValidateQueryStringSignature(request.Url.Query, messageName, Convert.FromBase64String(request.QueryString[Saml2Constants.Message.Signature]), signatureValidationCertificate);
            saml2RequestResponse.Read(DecompressResponse(request.QueryString[messageName]));
            XmlDocument = saml2RequestResponse.XmlDocument;
            return saml2RequestResponse;
        }

        private void ValidateQueryStringSignature(string queryString, string messageName, byte[] signatureValue, X509Certificate2 signatureValidationCertificate)
        {
            var saml2Sign = new Saml2Sign(signatureValidationCertificate.PublicKey.Key);
            Signature = Encoding.UTF8.GetString(signatureValue);

            if (!saml2Sign.CheckSignature(new RawSaml2QueryString(queryString, messageName).SignedQueryString, signatureValue))
            {
                throw new Saml2ResponseException("Signature is invalid (SHA256 algorithm is not supported).");
            }
        }

        private string DecompressResponse(string value)
        {
            using (var originalStream = new MemoryStream(Convert.FromBase64String(value)))
            using (var decompressedStream = new MemoryStream())
            {
                using (var deflateStream = new DeflateStream(originalStream, CompressionMode.Decompress))
                {
                    deflateStream.CopyTo(decompressedStream);
                }
                return Encoding.UTF8.GetString(decompressedStream.ToArray());
            }
        }
    }
}
