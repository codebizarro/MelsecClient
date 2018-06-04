using System.Configuration;

namespace TestClient
{
    public static class Configuration
    {
        public static string Address
        {
            get
            {
                return ConfigurationManager.AppSettings["address"];
            }
        }

        public static bool DoWrite
        {
            get
            {
                return bool.Parse(ConfigurationManager.AppSettings["dowrite"]);
            }
        }

        public static ushort Offset
        {
            get
            {
                return ushort.Parse(ConfigurationManager.AppSettings["offset"]);
            }
        }

        public static string ExpectedModel
        {
            get
            {
                return ConfigurationManager.AppSettings["expectedmodel"];
            }
        }
    }
}
