using System;

namespace ITfoxtec.Saml2
{
    [Serializable]
    public class Saml2ResponseException : Exception
    {
        public Saml2ResponseException() { }
        public Saml2ResponseException(string message) : base(message) { }
        public Saml2ResponseException(string message, Exception inner) : base(message, inner) { }
        protected Saml2ResponseException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context)
            : base(info, context) { }
    }

}
