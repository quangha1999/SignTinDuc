namespace SignTinDuc
{
    public partial class LoginForm : Form
    {
        public string Password { get; private set; }
        public LoginForm()
        {
            InitializeComponent();
        }

        private void btnLogin_Click(object sender, EventArgs e)
        {
            Password = txtPassword.Text;
            this.DialogResult = DialogResult.OK;
            this.Close();
        }

        private void LoginForm_Load(object sender, EventArgs e)
        {

        }
        public static string GetPassword(Icon icon, string model)
        {
            LoginForm form = new LoginForm();
            form.pictureIcon.Image = icon.ToBitmap();
            form.lblModel.Text = model;
            if (form.ShowDialog() == DialogResult.OK)
            {
                return form.Password;
            }
            return string.Empty;
        }
        private void btnHuy_Click(object sender, EventArgs e)
        {
            this.DialogResult = DialogResult.Cancel;
            this.Close();
        }
    }
}
