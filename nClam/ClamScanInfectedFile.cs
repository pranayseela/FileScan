namespace nClam
{
    /// <summary>
    /// The results of an infected file.
    /// </summary>
    public class ClamScanInfectedFile
    {
        /// <summary>
        /// The file name scanned, as returned by the ClamAV server
        /// </summary>
        public string FileName { get; set; } = string.Empty;

        /// <summary>
        /// The name of the virus detected by the ClamAV server
        /// </summary>
        public string VirusName { get; set; } = string.Empty;
    }
}