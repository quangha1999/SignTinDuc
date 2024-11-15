namespace SignTinDuc
{
    partial class LoginForm
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(LoginForm));
            txtPassword = new TextBox();
            label1 = new Label();
            btnLogin = new Button();
            btnHuy = new Button();
            label2 = new Label();
            pictureIcon = new PictureBox();
            lblModel = new Label();
            label3 = new Label();
            ((System.ComponentModel.ISupportInitialize)pictureIcon).BeginInit();
            SuspendLayout();
            // 
            // txtPassword
            // 
            txtPassword.Location = new Point(198, 96);
            txtPassword.Name = "txtPassword";
            txtPassword.PlaceholderText = "Nhập mã PIN";
            txtPassword.Size = new Size(239, 23);
            txtPassword.TabIndex = 0;
            txtPassword.UseSystemPasswordChar = true;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Font = new Font("Segoe UI", 12F, FontStyle.Regular, GraphicsUnit.Point, 0);
            label1.Location = new Point(111, 98);
            label1.Name = "label1";
            label1.Size = new Size(68, 21);
            label1.TabIndex = 1;
            label1.Text = "Mã PIN :";
            // 
            // btnLogin
            // 
            btnLogin.Location = new Point(196, 132);
            btnLogin.Name = "btnLogin";
            btnLogin.Size = new Size(106, 33);
            btnLogin.TabIndex = 3;
            btnLogin.Text = "Ký số";
            btnLogin.UseVisualStyleBackColor = true;
            btnLogin.Click += btnLogin_Click;
            // 
            // btnHuy
            // 
            btnHuy.Location = new Point(329, 132);
            btnHuy.Name = "btnHuy";
            btnHuy.Size = new Size(106, 33);
            btnHuy.TabIndex = 4;
            btnHuy.Text = "Hủy bỏ";
            btnHuy.UseVisualStyleBackColor = true;
            btnHuy.Click += btnHuy_Click;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Font = new Font("Segoe UI Semibold", 15.75F, FontStyle.Bold, GraphicsUnit.Point, 0);
            label2.Location = new Point(168, 13);
            label2.Name = "label2";
            label2.Size = new Size(176, 30);
            label2.TabIndex = 5;
            label2.Text = "Xác nhận mã PIN";
            // 
            // pictureIcon
            // 
            pictureIcon.Location = new Point(32, 32);
            pictureIcon.Name = "pictureIcon";
            pictureIcon.Size = new Size(45, 45);
            pictureIcon.SizeMode = PictureBoxSizeMode.CenterImage;
            pictureIcon.TabIndex = 6;
            pictureIcon.TabStop = false;
            // 
            // lblModel
            // 
            lblModel.AutoSize = true;
            lblModel.BackColor = SystemColors.Control;
            lblModel.Font = new Font("Segoe UI Semibold", 12F, FontStyle.Bold, GraphicsUnit.Point, 0);
            lblModel.ForeColor = SystemColors.HotTrack;
            lblModel.Location = new Point(200, 55);
            lblModel.Name = "lblModel";
            lblModel.Size = new Size(0, 21);
            lblModel.TabIndex = 7;
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Font = new Font("Segoe UI", 12F, FontStyle.Regular, GraphicsUnit.Point, 0);
            label3.Location = new Point(108, 55);
            label3.Name = "label3";
            label3.Size = new Size(68, 21);
            label3.TabIndex = 8;
            label3.Text = "Thiết bị :";
            // 
            // LoginForm
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;
            ClientSize = new Size(507, 200);
            Controls.Add(label3);
            Controls.Add(lblModel);
            Controls.Add(pictureIcon);
            Controls.Add(label2);
            Controls.Add(btnHuy);
            Controls.Add(btnLogin);
            Controls.Add(label1);
            Controls.Add(txtPassword);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            Icon = (Icon)resources.GetObject("$this.Icon");
            MaximizeBox = false;
            Name = "LoginForm";
            StartPosition = FormStartPosition.CenterScreen;
            Text = "Xác nhận PIN";
            Load += LoginForm_Load;
            ((System.ComponentModel.ISupportInitialize)pictureIcon).EndInit();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private TextBox txtPassword;
        private Label label1;
        private Button btnLogin;
        private Button btnHuy;
        private Label label2;
        private PictureBox pictureIcon;
        private Label lblModel;
        private Label label3;
    }
}
