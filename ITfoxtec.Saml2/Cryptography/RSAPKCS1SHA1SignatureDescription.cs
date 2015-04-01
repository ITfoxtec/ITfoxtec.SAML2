namespace ITfoxtec.Saml2.Cryptography
{
    using System;
    using System.Security.Cryptography;

    public sealed class RSAPKCS1SHA1SignatureDescription : SignatureDescription
    {
        public RSAPKCS1SHA1SignatureDescription()
        {
            base.KeyAlgorithm = typeof(RSACryptoServiceProvider).FullName;
            base.DigestAlgorithm = typeof(SHA1Managed).FullName;
            base.FormatterAlgorithm = typeof(RSAPKCS1SignatureFormatter).FullName;
            base.DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).FullName;
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }

            RSAPKCS1SignatureDeformatter deformatter = new RSAPKCS1SignatureDeformatter(key);
            deformatter.SetHashAlgorithm("SHA1");
            return deformatter;
        }

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }

            RSAPKCS1SignatureFormatter formatter = new CngRSAPKCS1SignatureFormatter(key);
            formatter.SetHashAlgorithm("SHA1");
            return formatter;
        }

    }
}
