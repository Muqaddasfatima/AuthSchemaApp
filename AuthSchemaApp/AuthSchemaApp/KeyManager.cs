using System.Security.Cryptography;

namespace AuthSchemaApp
{
    public class KeyManager
    {
        public KeyManager()
        {

            RsaKey = RSA.Create();
            if (File.Exists("Key"))
            {
                RsaKey.ImportRSAPrivateKey(File.ReadAllBytes("Key") , out _);
            }
            else
            {
                var privateKey = RsaKey.ExportRSAPrivateKey();
                File.WriteAllBytes("Key", privateKey);
            }
        }


        public RSA RsaKey { get; private set; }
    }

}