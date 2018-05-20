using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Windows;
using System.Xml.Linq;
using System.Windows.Controls;

namespace EncryptorProject
{
    static class FileEncryption
    {
        public delegate void ProgressUpdate(int i);
        public static ProgressUpdate ProgressUpdater;
        private static string AlgorithmNamelgorithmName = "3DES";
        public static byte[] Key;
        public static byte[] IV;
        public static CipherMode CipheringMode;
        public static int BufferSize;
        public static int KeySize;
        public static int FeedbackSize;
        public static List<User> Users;

        public static void InitializeEncryption(string inputFile, string outputFile)
        {
            var xdoc = new XDocument(
                new XElement("EncryptedFileHeader",
                    new XElement("Algorithm", AlgorithmNamelgorithmName),
                    new XElement("KeySize", KeySize.ToString()),
                    new XElement("FeedbackSize", FeedbackSize.ToString()),
                    new XElement("CipherMode", CipheringMode.ToString()),
                    new XElement("IV", Convert.ToBase64String(IV)),
                    new XElement("FileExtension", Path.GetExtension(inputFile)),
                    new XElement("ApprovedUsers",
                        from user in Users
                        select new XElement("User",
                            new XElement("Email", user.Email),
                            new XElement("SessionKey", RSA.EncryptToString(Key, user.GetPublicKey()))
                        )
                    )
                )
            );

            using (var writer = new StreamWriter(outputFile, false))
            {
                try
                {
                    xdoc.Save(writer);
                    writer.Write("\r\nDATA\r\n");
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error: " + ex);
                }
                
            }

            if (EncryptFile(inputFile, outputFile))
                MessageBox.Show("Successfuly written to file");
        }

        public static void LoadPossibleRecipientsAndFileType(string inputFile, ListBox receivers, Label extension)
        {
            var isSupportedFile = false;

            //read the header to memory
            using (var ms = new MemoryStream())
            {
                using (var s = File.OpenText(inputFile))
                {
                    while (!s.EndOfStream)
                    {
                        var l = s.ReadLine();
                        if (l.Contains("DATA"))
                        {
                            isSupportedFile = true;
                            break;
                        }
                            
                        ms.Write(Encoding.ASCII.GetBytes(l.ToCharArray()), 0, l.Length);
                    }
                }

                if (!isSupportedFile)
                {
                    MessageBox.Show("Incorrect file");
                    return;
                }

                //read settings from header
                ms.Position = 0;
                var xdoc = XDocument.Load(ms);
                var root = xdoc.Element("EncryptedFileHeader");

                extension.Content = root.Element("FileExtension").Value;

                var emails = root
                    .Element("ApprovedUsers")
                    .Elements()
                    .Select(element => element.Element("Email").Value)
                    .ToList();

                var allUsers = User.LoadUsers().ToDictionary(x => x.Email, x => x);

                receivers.Items.Clear();
                foreach (var email in emails)
                {
                    if (allUsers.ContainsKey(email))
                    {
                        receivers.Items.Add(allUsers[email]);
                    }
                }
            }
        }

        public static void InitializeDecryption(string inputFile, string outputFile, User currentUser, string password)
        {
            var isSupportedFile = false;
            //read the header to memory
            using (var ms = new MemoryStream())
            {
                using (var s = File.OpenText(inputFile))
                {
                    while (!s.EndOfStream)
                    {
                        var l = s.ReadLine();
                        if (l.Contains("DATA"))
                        {
                            isSupportedFile = true;
                            break;
                        }
                            
                        ms.Write(Encoding.ASCII.GetBytes(l.ToCharArray()), 0, l.Length);
                    }
                }

                if (!isSupportedFile)
                {
                    MessageBox.Show("Incorrect file");
                    return;
                }

                //write settings from header
                ms.Position = 0;
                var xdoc = XDocument.Load(ms);
                var root = xdoc.Element("EncryptedFileHeader");
                AlgorithmNamelgorithmName = root.Element("Algorithm").Value;
                KeySize = Int32.Parse(root.Element("KeySize").Value);
                FeedbackSize = Int32.Parse(root.Element("FeedbackSize").Value);

                var extension = root.Element("FileExtension").Value;
                var outputExtension = Path.GetExtension(outputFile);
                if (outputExtension != extension)
                {
                    MessageBox.Show("File extension was change to " + extension);
                    if (string.IsNullOrEmpty(outputExtension))
                        outputFile += extension;
                    else
                        outputFile.Replace(outputExtension, extension);
                }

                Enum.TryParse(root.Element("CipherMode").Value, out CipheringMode);
                IV = Convert.FromBase64String(root.Element("IV").Value);
                
                var usersAndKeys = root
                    .Element("ApprovedUsers")
                    .Elements()
                    .Select(element => new Tuple<string, string>(element.Element("Email").Value, element.Element("SessionKey").Value))
                    .ToList();
               
                foreach (var user in usersAndKeys)
                {
                    if (user.Item1 == currentUser.Email)
                    {
                        Key = RSA.DecryptFromString(user.Item2, currentUser.GetPrivateKey(password), KeySize);
                        break;
                    }
                }
            }
            
            if (DecryptFile(inputFile, outputFile))
                MessageBox.Show("File successfuly decrypted");
        }

        private static bool EncryptFile(string inputFile, string outputFile)
        {
            try
            {
                using (var tripleDESAlgorithm = TripleDES.Create())
                {
                    tripleDESAlgorithm.KeySize = KeySize;
                    tripleDESAlgorithm.Mode = CipheringMode;
                    tripleDESAlgorithm.FeedbackSize = FeedbackSize;
                    tripleDESAlgorithm.Key = Key;
                    tripleDESAlgorithm.IV = IV;
                    tripleDESAlgorithm.Padding = PaddingMode.Zeros;

                    MessageBox.Show($"Starting encryption, parameters:\nkey size: {KeySize}\nfeedback size: {FeedbackSize}\nmode: {CipheringMode.ToString()}");

                    var encryptor = tripleDESAlgorithm.CreateEncryptor(tripleDESAlgorithm.Key, tripleDESAlgorithm.IV);
                    var buffer = new byte[BufferSize];
                    using (var output = File.Open(outputFile, FileMode.Append))
                    using (var cs = new CryptoStream(output, encryptor, CryptoStreamMode.Write))
                    using (var bw = new BinaryWriter(cs))
                    using (var input = File.OpenRead(inputFile))
                    {
                        var count = 0;
                        var i = 0.0d;
                        var totalSize = input.Length / BufferSize;
                        while ((count = input.Read(buffer, 0, BufferSize)) > 0)
                        {
                            bw.Write(buffer, 0, count);
                            i++;
                            ProgressUpdater((int)(i / totalSize * 100.0)); //calling progress update delegate (progress bar function)
                        }
                    }
                }
                return true;
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message, "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return false;
        }

        private static bool DecryptFile(string inputFile, string outputFile)
        {
            try
            {
                using (var tripleDESAlgorithm = TripleDES.Create())
                {
                    tripleDESAlgorithm.KeySize = KeySize;
                    tripleDESAlgorithm.Mode = CipheringMode;
                    tripleDESAlgorithm.FeedbackSize = FeedbackSize;
                    tripleDESAlgorithm.Key = Key;
                    tripleDESAlgorithm.IV = IV;
                    tripleDESAlgorithm.Padding = PaddingMode.Zeros;

                    MessageBox.Show($"Starting decryption, parameters:\nkey size: {KeySize}\nfeedback size: {FeedbackSize}\nmode: {CipheringMode.ToString()}");

                    var decryptor = tripleDESAlgorithm.CreateDecryptor(tripleDESAlgorithm.Key, tripleDESAlgorithm.IV);
                    var buffer = new byte[BufferSize];

                    using (var output = File.Open(outputFile, FileMode.Create))
                    using (var cs = new CryptoStream(output, decryptor, CryptoStreamMode.Write))
                    using (var bw = new BinaryWriter(cs))
                    using (var input = File.OpenRead(inputFile))
                    {
                        //keep reading until we hit data label (we don't want to decrypt header)
                        var found = false;
                        while (!found)
                        {
                            if (ContainsDATASegment(input))
                            {
                                found = true;
                            }
                        }
                        var count = 0;
                        var i = 0.0d;
                        var totalSize = input.Length / BufferSize;
                        while ((count = input.Read(buffer, 0, BufferSize)) > 0)
                        {
                            bw.Write(buffer, 0, count);
                            i++;
                            ProgressUpdater((int)(i / totalSize * 100.0));
                        }
                    }
                }
                return true;
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message, "ERROR", MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }

        private static bool ContainsDATASegment(FileStream input)
        {
            return input.ReadByte() == 'D' &&
                                input.ReadByte() == 'A' &&
                                input.ReadByte() == 'T' &&
                                input.ReadByte() == 'A' &&
                                input.ReadByte() == '\r' &&
                                input.ReadByte() == '\n';
        }

        public static byte[] EncryptPrivateKey(string content, byte[] password)
        {
            var valueBytes = Encoding.UTF8.GetBytes(content);
            byte[] encrypted;
            using (var tripleDES = TripleDES.Create())
            {
                tripleDES.Key = password;
                tripleDES.GenerateIV();
                tripleDES.Mode = CipherMode.ECB;
                tripleDES.CreateEncryptor(tripleDES.Key, tripleDES.IV);

                using (var encryptor = tripleDES.CreateEncryptor(tripleDES.Key, tripleDES.IV))
                using (var to = new MemoryStream())
                {
                    to.Write(tripleDES.IV, 0, 8);
                    using (var writer = new CryptoStream(to, encryptor, CryptoStreamMode.Write))
                    {
                        writer.Write(valueBytes, 0, valueBytes.Length);
                        writer.FlushFinalBlock();
                        encrypted = to.ToArray();
                    }
                }
                tripleDES.Clear();
            }

            return encrypted;
        }

        public static string DecryptPrivateKey(byte[] content, byte[] password)
        {
            var _initialVector = new byte[8];
            Array.Copy(content, 0, _initialVector, 0, 8);
           
            byte[] decrypted;
            var decryptedByteCount = 0;
            using (var tripleDES = TripleDES.Create())
            {
                tripleDES.Key = password;
                tripleDES.IV = _initialVector;
                tripleDES.Mode = CipherMode.ECB;
                tripleDES.CreateEncryptor(tripleDES.Key, tripleDES.IV);

                try
                {
                    using (var decryptor = tripleDES.CreateDecryptor(tripleDES.Key, tripleDES.IV))
                    using (var from = new MemoryStream(content))
                    {
                        from.Read(_initialVector, 0, 8);
                        using (var reader = new CryptoStream(from, decryptor, CryptoStreamMode.Read))
                        {
                            decrypted = new byte[content.Length];
                            decryptedByteCount = reader.Read(decrypted, 0, decrypted.Length);
                        }
                    }
                }
                catch (Exception e)
                {
                    return String.Empty;
                }
                tripleDES.Clear();
            }

            return Encoding.UTF8.GetString(decrypted, 0, decryptedByteCount);
        }
    }
}
