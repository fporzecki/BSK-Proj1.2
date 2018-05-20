using System.Linq;
using System.Windows;
using System.Windows.Controls;

namespace EncryptorProject
{
    public partial class ReceiversWindow : Window
    {

        private ListBox _receivers;
       
        public ReceiversWindow(ListBox receivers) 
        {
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            InitializeComponent();
            listBox.SelectionMode = SelectionMode.Multiple;
            listBox.ItemsSource = User.LoadUsers();
            _receivers = receivers;
        }


        private void button_Click(object sender, RoutedEventArgs e)
        {
            foreach (User item in listBox.SelectedItems)
            {
                if (!_receivers.Items.Cast<User>().Contains(item))
                {
                    _receivers.Items.Add(item);
                }

                Close();
            }
        }
    }
}
