using System.Collections.Generic;
using System.Windows;
using System.Windows.Input;

namespace EncryptorProject
{
    public partial class RNGWindow : Window
    {
        public delegate void CallbackDelegate(List<Point> coordinates);
        CallbackDelegate callbackFunction;
        List<Point> _coordinates;
        int clicks = 0;

        public RNGWindow(CallbackDelegate func)
        {
            InitializeComponent();
            callbackFunction = func;

            _coordinates = new List<Point>();
        }

        private void UserClickingInput_Canvas_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            clicksCounterLabel.Content = (++clicks).ToString() + " / 8";
            _coordinates.Add(e.GetPosition(userClickingInputCanvas));

            if (_coordinates.Count == 8)
            {
                callbackFunction(_coordinates);
                Close();
            }
        }
    }
}
