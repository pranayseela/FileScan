using System;
using System.Linq;
using System.Threading.Tasks;
using nClam;
using Microsoft.Azure; // Namespace for Azure Configuration Manager
using Microsoft.WindowsAzure.Storage; // Namespace for Storage Client Library
using Microsoft.WindowsAzure.Storage.Blob; // Namespace for Azure Blobs
using Microsoft.WindowsAzure.Storage.File; // Namespace for Azure Files

class Program
{
    static async Task Main(string[] args)
    {
        var clam = new ClamClient("localhost", 3310);
        //The current directory is C Drive and a text file in it.
        var scanResult = await clam.ScanFileOnServerAsync("C:\\test.txt");  //any file you would like!

        switch (scanResult.Result)
        {
            case ClamScanResults.Clean:
                Console.WriteLine("The file is clean!");
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
            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(
                CloudConfigurationManager.GetSetting("StorageConnectionString"));

            // Create the blob client.
            CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();

            // Retrieve reference to a previously created container.
            CloudBlobContainer container = blobClient.GetContainerReference("container1");

            // Retrieve reference to a blob named "myblob".
            CloudBlockBlob blockBlob = container.GetBlockBlobReference("myblob1");

            // Create or overwrite the "myblob" blob with contents from a local file.
            using (var fileStream = System.IO.File.OpenRead(@"C:\\test.txt"))
            {
                blockBlob.UploadFromStream(fileStream);
            }
        }
        else if (scanResult.Result == ClamScanResults.VirusDetected)
        {
            Console.WriteLine("Virus Found!");
            Console.WriteLine("Virus name: {0}", scanResult.InfectedFiles.First().VirusName);
        }
        else
        {
            Console.WriteLine("File not found");
        }


    }
}