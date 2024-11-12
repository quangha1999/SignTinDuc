namespace SignTinDuc
{
    partial class Form1
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
            textBox1 = new TextBox();
            label1 = new Label();
            btnChangePin = new Button();
            btnLogin = new Button();
            btnHuy = new Button();
            label2 = new Label();
            pictureIcon = new PictureBox();
            ((System.ComponentModel.ISupportInitialize)pictureIcon).BeginInit();
            SuspendLayout();
            // 
            // textBox1
            // 
            textBox1.Location = new Point(188, 75);
            textBox1.Name = "textBox1";
            textBox1.Size = new Size(357, 23);
            textBox1.TabIndex = 0;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new Point(115, 78);
            label1.Name = "label1";
            label1.Size = new Size(46, 15);
            label1.TabIndex = 1;
            label1.Text = "Mã PIN";
            // 
            // btnChangePin
            // 
            btnChangePin.Location = new Point(188, 137);
            btnChangePin.Name = "btnChangePin";
            btnChangePin.Size = new Size(106, 33);
            btnChangePin.TabIndex = 2;
            btnChangePin.Text = "Đổi mã pin";
            btnChangePin.UseVisualStyleBackColor = true;
            // 
            // btnLogin
            // 
            btnLogin.Location = new Point(315, 137);
            btnLogin.Name = "btnLogin";
            btnLogin.Size = new Size(106, 33);
            btnLogin.TabIndex = 3;
            btnLogin.Text = "Đăng nhập";
            btnLogin.UseVisualStyleBackColor = true;
            // 
            // btnHuy
            // 
            btnHuy.Location = new Point(439, 137);
            btnHuy.Name = "btnHuy";
            btnHuy.Size = new Size(106, 33);
            btnHuy.TabIndex = 4;
            btnHuy.Text = "Hủy bỏ";
            btnHuy.UseVisualStyleBackColor = true;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new Point(188, 22);
            label2.Name = "label2";
            label2.Size = new Size(98, 15);
            label2.TabIndex = 5;
            label2.Text = "Xác nhận mã PIN";
            // 
            // pictureIcon
            // 
            pictureIcon.Location = new Point(31, 22);
            pictureIcon.Name = "pictureIcon";
            pictureIcon.Size = new Size(53, 50);
            pictureIcon.TabIndex = 6;
            pictureIcon.TabStop = false;
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(800, 450);
            Controls.Add(pictureIcon);
            Controls.Add(label2);
            Controls.Add(btnHuy);
            Controls.Add(btnLogin);
            Controls.Add(btnChangePin);
            Controls.Add(label1);
            Controls.Add(textBox1);
            Name = "Form1";
            Text = "Xác nhận PIN";
            ((System.ComponentModel.ISupportInitialize)pictureIcon).EndInit();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private TextBox textBox1;
        private Label label1;
        private Button btnChangePin;
        private Button btnLogin;
        private Button btnHuy;
        private Label label2;
        private PictureBox pictureIcon;
    }
}
