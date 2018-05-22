using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Text.RegularExpressions;
using System.Windows.Threading;
using System.Security.Cryptography;

namespace EncryptorProject
{
    public partial class MainWindow : Window
    {
        TripleDES TripleDESHelper = TripleDES.Create();

        public MainWindow()
        {
            InitializeComponent();
            receiversListBox.SelectionMode = SelectionMode.Multiple;
            FileEncryption.ProgressUpdater = (
                (int i) => encryptionProgressBar.Dispatcher.Invoke(
                    () => encryptionProgressBar.Value = i,
                    DispatcherPriority.Background
                )
            );
        }

        private void UpdateRNG(List<Point> coordinates)
        {
            var bytes = new List<byte>();
            foreach (var coordinate in coordinates)
            {
                bytes.Add(Convert.ToByte(coordinate.X));
                bytes.Add(Convert.ToByte(coordinate.Y));
            }
            
            using (var uptime = new PerformanceCounter("System", "System Up Time"))
            {
                uptime.NextValue();    
                bytes.AddRange(BitConverter.GetBytes(uptime.NextValue()));
            }
            
            FileEncryption.Key = GetSaltBytes(Int32.Parse(keySizeComboBox.Text) / 8);
            encryptFile_Button.IsEnabled = true;
        }

        private void PerformRNG()
        {
            var bytes = new List<byte>();

            using (var uptime = new PerformanceCounter("System", "System Up Time"))
            {
                uptime.NextValue();
                bytes.AddRange(BitConverter.GetBytes(uptime.NextValue()));
            }

            FileEncryption.Key = GetSaltBytes(Int32.Parse(keySizeComboBox.Text) / 8);
            encryptFile_Button.IsEnabled = true;
        }

        public static byte[] GetSaltBytes(int length)
        {
            var bytes = new byte[length];
            for (int i = 0; i < length; i++)
                bytes[i] = (byte)((i + 1) % 10);
            return bytes;
        }

        private CipherMode GetSelectedCipherMode()
        {
            if (modeECB.IsChecked == true)
                return CipherMode.ECB;
            if (modeCBC.IsChecked == true)
                return CipherMode.CBC;
            if (modeCFB.IsChecked == true)
                return CipherMode.CFB;
            if (modeOFB.IsChecked == true)
                return CipherMode.OFB;
            return CipherMode.ECB;
        }

        private string ValidateInputPath(string path)
        {
            if (String.IsNullOrEmpty(path)) return "Input file was not chosen!";
            if (!File.Exists(path)) return "Input file doesn't exist!";
            return null;
        }

        private string ValidateOutputPath(string path)
        {
            if (String.IsNullOrEmpty(path)) return "Destination file was not chosen!";
            //if (File.Exists(path)) return "Destination file already exists!";
            if (!Path.IsPathRooted(path)) return "Incorrect path for destination file!";

            var pathAndFileName = path;

            var path2 = pathAndFileName.Substring(0, pathAndFileName.LastIndexOf("\\"));
            try
            {
                if (!Directory.Exists(path2))
                    Directory.CreateDirectory(path2);
            }
            catch
            {
                return "Destination directory was not chosen!";
            }

            return null;
        }

        private void InputFile_Button_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
                inputFile_TextBox.Text = openFileDialog.FileName;
        }

        private void DecryptionInputButton_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                decryptionInputFileBox.Text = openFileDialog.FileName;
                FileEncryption.LoadPossibleRecipientsAndFileType(openFileDialog.FileName, decryptionRecipientsList, extension_Label);
            }
        }

        private void GenerateRandomNumber_Button_Click(object sender, RoutedEventArgs e)
        {
            PerformRNG();
            //var win2 = new RNGWindow(UpdateRNG);
            //win2.ShowDialog();
        }
        
        private void EncryptFile_Button_Click(object sender, RoutedEventArgs e)
        {
            var inputFilePath = inputFile_TextBox.Text;
            var fileRootPath = Path.GetDirectoryName(inputFilePath);
            var inputFileError = ValidateInputPath(inputFilePath);

            var outputFileName = Path.Combine(fileRootPath, outputFile_TextBox.Text);
            var outputFileError = ValidateOutputPath(outputFileName);

            if(inputFileError != null)
            {
                MessageBox.Show(inputFileError);
                return;
            }

            if(outputFileError != null)
            {
                MessageBox.Show(outputFileError);
                return;
            }

            try
            {
                FileEncryption.Users = receiversListBox.Items.Cast<User>().ToList();
                FileEncryption.CipheringMode = GetSelectedCipherMode();
                FileEncryption.KeySize = Int32.Parse(keySizeComboBox.Text);
                FileEncryption.BufferSize = 1 << 22;
                //FileEncryption.FeedbackSize = Int32.Parse(feedbackSizeComboBox.Text);
                FileEncryption.IV = GetSaltBytes(8);

                FileEncryption.InitializeEncryption(inputFilePath, outputFileName);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error during decryption: " + ex);
            }
        }

        private void ModeRadio_Checked(object sender, RoutedEventArgs e)
        {
            if (validBlockSize_Label == null)
                return;
            TripleDESHelper.Mode = GetSelectedCipherMode();

            //if (TripleDESHelper.Mode == CipherMode.CFB || TripleDESHelper.Mode == CipherMode.OFB)
            //    feedbackSize_GroupBox.Visibility = Visibility.Visible;
            //else
            //    feedbackSize_GroupBox.Visibility = Visibility.Hidden;

            String text = String.Format("{0} - {1}", TripleDESHelper.LegalBlockSizes[0].MinSize, TripleDESHelper.LegalBlockSizes[0].MaxSize);
            if (TripleDESHelper.LegalBlockSizes[0].MinSize == TripleDESHelper.LegalBlockSizes[0].MaxSize)
                text = String.Format("{0}", TripleDESHelper.LegalBlockSizes[0].MinSize.ToString());
        }

        private void DecryptFile_Button_Click(object sender, RoutedEventArgs e)
        {
            var inputFilePath = decryptionInputFileBox.Text;
            var fileRootPath = Path.GetDirectoryName(inputFilePath);
            var inputFileError = ValidateInputPath(inputFilePath);

            var extension = extension_Label.Content.ToString();

            var outputFileName = Path.Combine(fileRootPath, decryptionOutputFileBox.Text);
            try
            {
                if (!string.IsNullOrEmpty(Path.GetExtension(outputFileName)))
                    throw new ArgumentException("You don't need to add file extension in the name - it's appended in the encrypted file. Provided extension will be overwritten.");
            }
            catch (ArgumentException ex)
            {
                outputFileName = Path.GetFileNameWithoutExtension(outputFileName);
                outputFileName += extension;
                outputFileName = Path.Combine(fileRootPath, outputFileName);
                MessageBox.Show(ex.Message);
            }

            var outputFileError = ValidateOutputPath(outputFileName);

            if (inputFileError != null)
            {
                MessageBox.Show(inputFileError);
                return;
            }

            if (outputFileError != null)
            {
                MessageBox.Show(outputFileError);
                return;
            }

            try
            {
                FileEncryption.BufferSize = 1 << 22;


                var selectedUser = (User)decryptionRecipientsList.SelectedItem;
                if(selectedUser == null)
                {
                    MessageBox.Show("Please choose a user.");
                    return;
                }
                var password = decryptionPassword.Password;
                
                FileEncryption.InitializeDecryption(inputFilePath, outputFileName, selectedUser, password);
            }
            catch (Exception)
            {
                MessageBox.Show("Error encountered during decryption");
            }
        }
       
        private void AddUser_Button_Click(object sender, RoutedEventArgs e)
        {
            var userEmail = email.Text;
            var userPassword = passwordBox.Password;
            var passwordRepeated = passwordBoxRepeat.Password;

            var passwordError = User.ValidatePassword(userPassword);
            var repeatError = ValidateRepeatedPassoword();

            if(passwordError == null && repeatError == null && !String.IsNullOrEmpty(userEmail))
            {
                new User(userEmail, userPassword);
                MessageBox.Show("Added new user: " + userEmail);
            }
        }

        private string ValidateRepeatedPassoword()
        {
            if (passwordBoxRepeat.Password != passwordBox.Password)
            {
                return "Passwords must match!";
            }
            return null;
        }
        
        private void PasswordBoxRepeat_PasswordChanged(object sender, RoutedEventArgs e)
        {
            var error = ValidateRepeatedPassoword();

            if (error != null) passwordReapetError.Content = error;
            else passwordReapetError.Content = "";
        }

        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            var error = User.ValidatePassword(passwordBox.Password);

            if (error != null) passwordError.Content = error;
            else passwordError.Content = "";
        }

        private void AddReceiverClick(object sender, RoutedEventArgs e)
        {
            new ReceiversWindow(receiversListBox).Show();
        }

        private void RemoveReceiverClick(object sender, RoutedEventArgs e)
        {
            List<User> selectedItems = receiversListBox.SelectedItems.Cast<User>().ToList();

            foreach (User item in selectedItems)
            {
                receiversListBox.Items.Remove(item);
            }
        }

        private static bool IsTextAllowed(string text) {
            Regex regex = new Regex("[^0-9.-]+"); //regex that matches disallowed text
            return !regex.IsMatch(text);
        }

        private void BlockSize_TextBox_PreviewTextInput(object sender, System.Windows.Input.TextCompositionEventArgs e) {
            e.Handled = !IsTextAllowed(e.Text) || ((TextBox)sender).Text.Length >= 3;
        }

        private void KeySize_TextBox_PreviewTextInput(object sender, System.Windows.Input.TextCompositionEventArgs e) {
            e.Handled = !IsTextAllowed(e.Text) || ((TextBox)sender).Text.Length >= 3;
        }

        private void TabItem_Selected(object sender, RoutedEventArgs e)
        {
            encryptionProgressBar.Visibility = Visibility.Hidden;
        }

        private void TabItem_Selected_1(object sender, RoutedEventArgs e)
        {
            encryptionProgressBar.Visibility = Visibility.Visible;
        }
    }
}
