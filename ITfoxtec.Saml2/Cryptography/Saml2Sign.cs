using System;
using System.Security.Cryptography;
using System.Text;
using Security.Cryptography;

namespace ITfoxtec.Saml2.Cryptography
{
    public class Saml2Sign
    {
        public AsymmetricAlgorithm Algorithm { get; protected set; }

        public Saml2Sign(AsymmetricAlgorithm algorithm)
        {
            Algorithm = algorithm;
        }

        public byte[] SignData(byte[] data)
        {
            RSACryptoServiceProvider rsaCryptoServiceProvider = Algorithm as RSACryptoServiceProvider;
            if (rsaCryptoServiceProvider != null)
            {
                return rsaCryptoServiceProvider.SignData(data, new SHA1CryptoServiceProvider());
            }

            DSACryptoServiceProvider dsaCryptoServiceProvider = Algorithm as DSACryptoServiceProvider;
            if (dsaCryptoServiceProvider != null)
            {
                return dsaCryptoServiceProvider.SignData(data);
            }

            RSACng rsaCng = Algorithm as RSACng;
            if (rsaCng != null)
            {
                return rsaCng.SignData(data);
            }

            throw new NotSupportedException("The given AsymmetricAlgorithm is not supported.");
        }

        internal bool CheckSignature(string signedData, byte[] signatureValue, string signatureAlgorithm)
        {
            SignatureDescription signatureDescription = (SignatureDescription)CryptoConfig.CreateFromName(signatureAlgorithm);
            HashAlgorithm hashAlgorithm = signatureDescription.CreateDigest();
            byte[] hash = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(signedData));

            RSACryptoServiceProvider rsa = Algorithm as RSACryptoServiceProvider;
            if (rsa != null)
            {
                return rsa.VerifyHash(hash, signatureDescription.DigestAlgorithm, signatureValue);
            }

            DSA dsa = Algorithm as DSA;
            if (dsa != null)
            {
                return dsa.VerifySignature(hash, signatureValue);
            }

            throw new NotSupportedException("Only RSA and DSA are supported");
        }
    }
}
