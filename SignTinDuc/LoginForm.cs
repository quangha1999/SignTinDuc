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

        }

        private void LoginForm_Load(object sender, EventArgs e)
        {

        }
        public static string GetPassword()
        {
            LoginForm form = new LoginForm();
            if (form.ShowDialog() == DialogResult.OK)
            {
                return form.Password;
            }
            return string.Empty; // Trả về mật khẩu trống nếu form bị đóng mà không xác nhận
        }
    }
}
