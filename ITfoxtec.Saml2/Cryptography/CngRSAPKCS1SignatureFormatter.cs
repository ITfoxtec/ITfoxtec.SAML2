namespace ITfoxtec.Saml2.Cryptography
{
    using System;
    using System.Diagnostics.Contracts;
    using System.Security.Cryptography;
    using Security.Cryptography;

    public class CngRSAPKCS1SignatureFormatter : RSAPKCS1SignatureFormatter
    {
        private RSA rsaKey;
        private string oid;

        public CngRSAPKCS1SignatureFormatter()
        {
        }

        public CngRSAPKCS1SignatureFormatter(AsymmetricAlgorithm key)
            : base(key)
        {
            this.rsaKey = (RSA)key;
        }

        /// <summary>
        ///   Sets the private key to use for creating the signature.
        /// </summary>
        /// <param name="key">The instance of the <see cref="T:System.Security.Cryptography.RSA"/> algorithm that holds the private key.</param>
        /// <exception cref="T:System.ArgumentNullException"><paramref name="key"/> is null.</exception>
        public override void SetKey(AsymmetricAlgorithm key)
        {
            base.SetKey(key);
            this.rsaKey = (RSA)key;
        }

        /// <summary>
        /// Sets the hash algorithm to use for creating the signature.
        /// </summary>
        /// <param name="strName">The name of the hash algorithm to use for creating the signature. </param>
        public override void SetHashAlgorithm(string strName)
        {
            base.SetHashAlgorithm(strName);
            this.oid = CryptoConfig.MapNameToOID(strName);
        }

        /// <summary>
        ///   Creates the <see cref="T:System.Security.Cryptography.RSA" /> PKCS #1 signature for the specified data.
        /// </summary>
        /// <returns>
        ///   The digital signature for <paramref name="rgbHash" />.
        /// </returns>
        /// <param name="rgbHash">The data to be signed.</param>
        /// <exception cref="T:System.Security.Cryptography.CryptographicUnexpectedOperationException">The key is null.-or- The hash algorithm is null.</exception>
        /// <exception cref="T:System.ArgumentNullException">The <paramref name="rgbHash" /> parameter is null.</exception>
        /// <PermissionSet>
        ///   <IPermission class="System.Security.Permissions.KeyContainerPermission, mscorlib, Version=2.0.3600.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" version="1" Unrestricted="true"/>
        /// </PermissionSet>
        public override byte[] CreateSignature(byte[] rgbHash)
        {
            RSACng rsaCng = this.rsaKey as RSACng;
            if (rgbHash != null && rsaCng != null && this.oid != null)
            {
                CngAlgorithm hashAlgorithm = GetAlgIdFromOid(this.oid);
                return rsaCng.SignHash(rgbHash, hashAlgorithm);
            }

            return base.CreateSignature(rgbHash);
        }

        private static CngAlgorithm GetAlgIdFromOid(string oid)
        {
            Contract.Requires(oid != null);

            if (string.Equals(oid, "1.3.14.3.2.26", StringComparison.Ordinal))
            {
                return CngAlgorithm.Sha1;
            }

            if (string.Equals(oid, "2.16.840.1.101.3.4.2.1", StringComparison.Ordinal))
            {
                return CngAlgorithm.Sha256;
            }

            if (string.Equals(oid, "2.16.840.1.101.3.4.2.2", StringComparison.Ordinal))
            {
                return CngAlgorithm.Sha384;
            }

            if (string.Equals(oid, "2.16.840.1.101.3.4.2.3", StringComparison.Ordinal))
            {
                return CngAlgorithm.Sha512;
            }

            throw new NotSupportedException("The hash algorithm is not supported");
        }
    }
}
