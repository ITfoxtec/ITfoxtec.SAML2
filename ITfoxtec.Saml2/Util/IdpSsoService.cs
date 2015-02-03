using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ITfoxtec.Saml2.Util
{
    public class IdpSsoService
    {
        public string Binding { get; set; }
        public string Location { get; set; }
        public int Index { get; set; }
        public bool IsDefault { get; set; }

        public IdpSsoService(string binding, string location, int index, bool isDefault)
        {
            Binding = binding;
            Location = location;
            Index = index;
            IsDefault = isDefault;
        }

        public static class Constants
        {
            public const string SingleLogoutServiceTag = "SingleLogoutService";
            public const string SingleSignOnServiceTag = "SingleSignOnService";
            public const string ArtifactResolutionServiceTag = "ArtifactResolutionService";

            public const string BindingAttribute = "Binding";
            public const string LocationAttribute = "Location";
            public const string IndexAttribute = "index";
            public const string IsDefaultAttribute = "isDefault";
            public const string NameIDFormatTag = "NameIDFormat";


        }
    }
}
