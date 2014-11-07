using System.Security.Cryptography;
using System.Text;

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
            if (Algorithm is RSACryptoServiceProvider)
            {
                return (Algorithm as RSACryptoServiceProvider).SignData(data, new SHA1CryptoServiceProvider());
            }
            else
            {
                return (Algorithm as DSACryptoServiceProvider).SignData(data);
            }
        }

        internal bool CheckSignature(string signedData, byte[] signatureValue)
        {
            byte[] hash = new SHA1Managed().ComputeHash(Encoding.UTF8.GetBytes(signedData));

            if (Algorithm is RSACryptoServiceProvider)
            {
                return (Algorithm as RSACryptoServiceProvider).VerifyHash(hash, "SHA1", signatureValue);
            }
            else
            {
                return (Algorithm as DSA).VerifySignature(hash, signatureValue);
            }   
        }
    }
}
