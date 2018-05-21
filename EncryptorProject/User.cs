using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;

namespace EncryptorProject
{
    class User : IEquatable<User>
    {
        public string Email { get; }
        private string _privateKeyPath;
        private string _publicKeyPath;

        private static string _programDataDir =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FileEncryptionTool");

        private static string _publicKeysDir = Path.Combine(_programDataDir, "public");
        private static string _privateKeysDir = Path.Combine(_programDataDir, "private");
        
        public User(string email, string password)
        {
            this.Email = email;
            GenerateKeyPair(email, password);
        }

        private User(string email, string privateKeyPath, string publicKeyPath)
        {
            this.Email = email;
            this._privateKeyPath = privateKeyPath;
            this._publicKeyPath = publicKeyPath;
        }
        
        public static List<User> LoadUsers()
        {
            List<User> allUsers = new List<User>();

            if (!Directory.Exists(_programDataDir))
            {
                return allUsers;
            }

            string[] keyPaths = Directory.GetFiles(_publicKeysDir, "*");
            foreach (string publicKeyPath in keyPaths)
            {
                string email = Path.GetFileName(publicKeyPath);
                string privateKeyPath = Path.Combine(_privateKeysDir, email);
                allUsers.Add(new User(email, privateKeyPath, publicKeyPath));
            }

            return allUsers;
        }

        private static void CreateDirectory(string path)
        {
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }
        }

        private void GenerateKeyPair(string email, string password)
        {
            CreateDirectory(_publicKeysDir);
            CreateDirectory(_privateKeysDir);

            _publicKeyPath = Path.Combine(_publicKeysDir, email);
            _privateKeyPath = Path.Combine(_privateKeysDir, email);

            RSA.GenerateKeyPair(_publicKeyPath, _privateKeyPath, password);
        }

        public RSA.Key GetPublicKey()
        {
            return RSA.LoadPublicKey(_publicKeyPath);
        }

        public RSA.Key GetPrivateKey(string password)
        {
            return RSA.LoadPrivateKey(_privateKeyPath, password);
        }
        
        public bool Equals(User other)
        {
            return other.Email == Email;
        }

        public override string ToString()
        {
            return Email;
        }
        
        public static string ValidatePassword(string password)
        {
            if (password.Length < 10) return "At least 10 chars";
            else if (!password.Any(ch => !char.IsLetterOrDigit(ch))) return "At least 1 special character";

            return null;
        }
    }
}
