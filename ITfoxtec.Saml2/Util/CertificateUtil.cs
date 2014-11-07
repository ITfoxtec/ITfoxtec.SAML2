using System;
using System.Globalization;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Web;

namespace ITfoxtec.Saml2.Util
{
    public static class CertificateUtil
    {
        public static X509Certificate2 Load(string path)
        {
            return new X509Certificate2(GetFullPath(path));
        }

        public static X509Certificate2 Load(string path, string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentNullException("password");

            return new X509Certificate2(GetFullPath(path), password);
        }

        public static X509Certificate2 Load(string path, SecureString password)
        {
            if (password == null)
                throw new ArgumentNullException("password");

            return new X509Certificate2(GetFullPath(path), password);
        }

        private static string GetFullPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentNullException("path");

            if (HttpContext.Current != null)
            {
                path = HttpContext.Current.Server.MapPath(path);
            }
            return path;
        }


        public static X509Certificate2 LoadBytes(string certificate)
        {
            if (string.IsNullOrWhiteSpace(certificate))
                throw new ArgumentNullException("certificate");

            var encoding = new System.Text.UTF8Encoding();
            return new X509Certificate2(encoding.GetBytes(certificate));
        }

        public static X509Certificate2 LoadBytes(string certificate, string password)
        {
            if (string.IsNullOrWhiteSpace(certificate))
                throw new ArgumentNullException("certificate");

            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentNullException("password");

            var encoding = new System.Text.UTF8Encoding();
            return new X509Certificate2(encoding.GetBytes(certificate), password);
        }

        public static X509Certificate2 Load(StoreName name, StoreLocation location, X509FindType type, string findValue)
        {
            if (string.IsNullOrWhiteSpace(findValue))
                throw new ArgumentNullException("findValue");
            
            var store = new X509Store(name, location);
            store.Open(OpenFlags.ReadOnly);
            try
            {
                var certificates = store.Certificates.Find(type, findValue, false);

                if (certificates.Count != 1)
                {
                    throw new InvalidOperationException(
                        string.Format(CultureInfo.InvariantCulture,
                        "Finding certificate with [StoreName:{0}, StoreLocation:{1}, X509FindType: {2}, FindValue: {3}] matched {4} certificates. A unique match is required.",
                        name, location, type, findValue, certificates.Count));
                }

                return certificates[0];
            }
            finally
            {
                store.Close();
            }
        }
    }
}
