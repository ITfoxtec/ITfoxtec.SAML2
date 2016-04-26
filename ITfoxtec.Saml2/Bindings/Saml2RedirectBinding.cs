﻿using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Web;
using System.Xml;
using ITfoxtec.Saml2.Schemas;
using ITfoxtec.Saml2.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Saml2.Util;

namespace ITfoxtec.Saml2.Bindings
{
    public class Saml2RedirectBinding : Saml2Binding
    {
        public Uri RedirectLocation { get; protected set; }

        public string Signature { get; protected set; }
        public string SignatureAlgorithm { get; protected set; }

        public Saml2RedirectBinding Bind(Saml2Request saml2Request, X509Certificate2 signingCertificate = null)
        {
            return BindInternal(saml2Request, Saml2Constants.Message.SamlRequest, signingCertificate);
        }

        public Saml2RedirectBinding Bind(Saml2Response saml2Response, X509Certificate2 signingCertificate = null)
        {
            return BindInternal(saml2Response as Saml2Request, Saml2Constants.Message.SamlResponse, signingCertificate);
        }

        protected Saml2RedirectBinding BindInternal(Saml2Request saml2RequestResponse, string messageName, X509Certificate2 signingCertificate)
        {
            base.BindInternal(saml2RequestResponse, signingCertificate);

            var requestQueryString = string.Join("&", RequestQueryString(signingCertificate, messageName));
            if (signingCertificate != null)
            {
                requestQueryString = SigneQueryString(requestQueryString, signingCertificate);
            }

            RedirectLocation = new Uri(string.Join("?", saml2RequestResponse.Destination.Uri.OriginalString, requestQueryString));

            return this;
        }
        
        private string SigneQueryString(string queryString, X509Certificate2 signingCertificate)
        {
            var saml2Signed = new Saml2Sign(signingCertificate.PrivateKey);
            SignatureAlgorithm = signingCertificate.PrivateKey.SignatureAlgorithm;
            Signature = Convert.ToBase64String(saml2Signed.SignData(Encoding.UTF8.GetBytes(queryString)));

            return string.Join("&", queryString, string.Join("=", Saml2Constants.Message.Signature, HttpUtility.UrlEncode(Signature)));
        }

        private IEnumerable<string> RequestQueryString(X509Certificate2 signingCertificate, string messageName)
        {
            yield return string.Join("=", messageName, HttpUtility.UrlEncode(CompressRequest()));

            if (!string.IsNullOrWhiteSpace(RelayState))
            {
                yield return string.Join("=", Saml2Constants.Message.RelayState, HttpUtility.UrlEncode(RelayState));
            }

            if(signingCertificate != null)
            {
                yield return string.Join("=", Saml2Constants.Message.SigAlg, HttpUtility.UrlEncode(signingCertificate.PrivateKey.SignatureAlgorithm));
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
