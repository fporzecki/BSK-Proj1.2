using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace EncryptorProject
{
    public class RSA
    {
        public class Key
        {
            public string ContentXML { get; }

            public Key(string content)
            {
                ContentXML = content;
            }
        }
        
        private static bool _doOAEPPadding = true;
        
        public static byte[] Encrypt(byte[] content, Key publicKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKey.ContentXML);
                return rsa.Encrypt(content, _doOAEPPadding);
            }
        }

        public static string EncryptToString(byte[] content, Key publicKey)
        {
            var encoded = Encrypt(content, publicKey);
            Console.WriteLine(Encoding.UTF8.GetString(content));
            Console.WriteLine(Encoding.UTF8.GetString(encoded));

            return Convert.ToBase64String(encoded);
        }


        public static byte[] DecryptFromString(string content, Key privateKey, int keySize) 
        {
            var contentBytes = Convert.FromBase64String(content);

            if (String.IsNullOrEmpty(privateKey.ContentXML)) //wrong private key password
            {
                var rnd = new Random();
                var b = new byte[keySize/8];
                rnd.NextBytes(b);
                return b;
            }

            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(privateKey.ContentXML);

                return rsa.Decrypt(contentBytes, _doOAEPPadding);
            }
        }

        public static byte[] GenerateHash(string password, bool isForUserKeyProcessing = false)
        {
            var sha = SHA256Managed.Create();
            var passwordBytes = Encoding.UTF8.GetBytes(password);
            var hashed = sha.ComputeHash(passwordBytes);
            var keySize = isForUserKeyProcessing ? 192 : FileEncryption.KeySize;
            var result = new byte[keySize / 8];
            Buffer.BlockCopy(hashed, 0, result, 0, result.Length);
            return result;
        }

        public static void GenerateKeyPair(string publicKeyPath, string privateKeyPath, string privateKeyPassword)
        {
            using (var rsa = new RSACryptoServiceProvider(1024))
            {
                try
                {
                    File.WriteAllText(publicKeyPath, rsa.ToXmlString(false));
                    var passwordHash = GenerateHash(privateKeyPassword, true);
                    
                    var priv = FileEncryption.EncryptPrivateKey(rsa.ToXmlString(true), passwordHash);
                    File.WriteAllBytes(privateKeyPath,priv);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
        
        public static Key LoadPublicKey(string path)
        {
            return new Key(File.ReadAllText(path));
        }

        public static Key LoadPrivateKey(string path, string password)
        {
            var encryptedContent = File.ReadAllBytes(path);
            var passwordHash = GenerateHash(password, true);
            var decryptedConten = FileEncryption.DecryptPrivateKey(encryptedContent, passwordHash);
            
            return new Key(decryptedConten);
        }
    }
}
