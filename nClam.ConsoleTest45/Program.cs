using System;
using System.Linq;
using System.Threading.Tasks;
using nClam;
using System.Threading;
using Microsoft.Azure; // Namespace for Azure Configuration Manager
using Microsoft.WindowsAzure.Storage; // Namespace for Storage Client Library
using Microsoft.WindowsAzure.Storage.Blob; // Namespace for Azure Blobs
using Microsoft.WindowsAzure.Storage.File; // Namespace for Azure Files
using System.Windows.Forms;
using System.IO;
using System.Xml.Linq;


class Program
{
    static async Task Main(string[] args)
    {
        var clam = new ClamClient("localhost", 3310);
        string filePath = "C:\\test.txt";
        string filePath2 = "C:\\test.docx";


        await ScanAndUploadDocument(clam, filePath);
        Thread.Sleep(2000);
        await ScanAndUploadDocument(clam, filePath2);
        Console.ReadLine();
        
        
    }

    private static async Task ScanAndUploadDocument(ClamClient clam, string filePath)
    {
        //The current directory is C Drive and a text file in it.
        var scanResult = await clam.ScanFileOnServerAsync(@filePath);  //any file you would like!

        switch (scanResult.Result)
        {
            case ClamScanResults.Clean:
                Console.WriteLine("The file "+ filePath + " is clean!");
                break;
            case ClamScanResults.VirusDetected:
                Console.WriteLine("Virus Found!");
                Console.WriteLine("Virus name: {0}", scanResult.InfectedFiles.First().VirusName);
                break;
            case ClamScanResults.Error:
                Console.WriteLine("Woah an error occured! Error: {0}", scanResult.RawResult);
                break;
        }
        //if condition for checking scan success.

        if (scanResult.Result == ClamScanResults.Clean)
        {
            // Retrieve storage account from connection string.
            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(CloudConfigurationManager.GetSetting("StorageConnectionString"));

            // Create the blob client.
            CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();

            // Retrieve reference to a previously created container.
            CloudBlobContainer container = blobClient.GetContainerReference("container1");

            //string dateTime = DateTime.Now.ToString("MMM ddd d HH:mm yyyy");
            string dateTime = DateTime.Now.ToString("MMddHHmmss");


            string fileName = "file" + dateTime;
            CloudBlockBlob blockBlob = container.GetBlockBlobReference(fileName);


            using (var fileStream = System.IO.File.OpenRead(@filePath))
            {
                blockBlob.UploadFromStream(fileStream);
            }
        }
        else if (scanResult.Result == ClamScanResults.VirusDetected)
        {
            Console.WriteLine("Virus Found! Cannot upload the document.");
            Console.WriteLine("Virus name: {0}", scanResult.InfectedFiles.First().VirusName);
        }
        else
        {
            Console.WriteLine("File not found. Select appropriate file");
        }
    }

    
}