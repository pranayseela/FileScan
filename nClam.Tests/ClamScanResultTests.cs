using System;
using Xunit;

namespace nClam.Tests
{
    public class ClamScanResultTests
    {
        [Fact]
        public void OK_Response()
        {
            var result = new ClamScanResult(@"C:\test.txt: OK");

            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        [Fact]
        public void Error_Response()
        {
            var result = new ClamScanResult("error");

            Assert.Equal(ClamScanResults.Error, result.Result);
        }

        [Fact]
        public void VirusDetected_Response()
        {
            var result = new ClamScanResult(@"\\?\C:\test.txt: Eicar-Test-Signature FOUND");

            Assert.Equal(ClamScanResults.VirusDetected, result.Result);

            Assert.Single(result.InfectedFiles);

            Assert.Equal(@"\\?\C:\test.txt", result.InfectedFiles[0].FileName);
            Assert.Equal("Eicar-Test-Signature", result.InfectedFiles[0].VirusName);
        }

        [Fact]
        public void VirusDetected_MultipleFiles()
        {
            var result = new ClamScanResult(@"C:\file1.txt: Virus1 FOUND" + Environment.NewLine + @"C:\file2.txt: Virus2 FOUND");

            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
            Assert.Equal(2, result.InfectedFiles.Count);
            Assert.Equal(@"C:\file1.txt", result.InfectedFiles[0].FileName);
            Assert.Equal("Virus1", result.InfectedFiles[0].VirusName);
            Assert.Equal(@"C:\file2.txt", result.InfectedFiles[1].FileName);
            Assert.Equal("Virus2", result.InfectedFiles[1].VirusName);
        }

        [Fact]
        public void Non_Matching()
        {
            var result = new ClamScanResult(Guid.NewGuid().ToString());

            Assert.Equal(ClamScanResults.Unknown, result.Result);
        }

        [Fact]
        public void Null_RawResult_ThrowsException()
        {
            Assert.Throws<ArgumentNullException>(() => new ClamScanResult(null!));
        }
    }
}
