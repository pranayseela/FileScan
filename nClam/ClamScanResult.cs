namespace nClam
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;

    public class ClamScanResult
    {
        /// <summary>
        /// The raw string returned by the ClamAV server.
        /// </summary>
        public string RawResult { get; }

        /// <summary>
        /// The parsed results of scan.
        /// </summary>
        public ClamScanResults Result { get; }

        /// <summary>
        /// List of infected files with what viruses they are infected with. Empty collection if the Result is not VirusDetected.
        /// </summary>
        public ReadOnlyCollection<ClamScanInfectedFile> InfectedFiles { get; }

        public ClamScanResult(string rawResult)
        {
            RawResult = rawResult ?? throw new ArgumentNullException(nameof(rawResult));

            var resultLowered = rawResult.ToLowerInvariant();

#if NET45
            if (resultLowered.EndsWith("ok"))
            {
                Result = ClamScanResults.Clean;
                InfectedFiles = new ReadOnlyCollection<ClamScanInfectedFile>(new List<ClamScanInfectedFile>());
            }
            else if (resultLowered.EndsWith("error"))
            {
                Result = ClamScanResults.Error;
                InfectedFiles = new ReadOnlyCollection<ClamScanInfectedFile>(new List<ClamScanInfectedFile>());
            }
            else if (resultLowered.Contains("found"))
#else
            if (resultLowered.EndsWith("ok", StringComparison.Ordinal))
            {
                Result = ClamScanResults.Clean;
                InfectedFiles = new ReadOnlyCollection<ClamScanInfectedFile>(new List<ClamScanInfectedFile>());
            }
            else if (resultLowered.EndsWith("error", StringComparison.Ordinal))
            {
                Result = ClamScanResults.Error;
                InfectedFiles = new ReadOnlyCollection<ClamScanInfectedFile>(new List<ClamScanInfectedFile>());
            }
            else if (resultLowered.Contains("found", StringComparison.Ordinal))
#endif
            {
                Result = ClamScanResults.VirusDetected;
                InfectedFiles = ParseInfectedFiles(rawResult);
            }
            else
            {
                Result = ClamScanResults.Unknown;
                InfectedFiles = new ReadOnlyCollection<ClamScanInfectedFile>(new List<ClamScanInfectedFile>());
            }
        }

        private static ReadOnlyCollection<ClamScanInfectedFile> ParseInfectedFiles(string rawResult)
        {
            var infectedFiles = new List<ClamScanInfectedFile>();
            var lines = rawResult.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            
            foreach (var line in lines)
            {
#if NET45
                if (!line.EndsWith("found", StringComparison.CurrentCultureIgnoreCase))
                {
                    continue;
                }

                var foundIndex = line.LastIndexOf(" FOUND", StringComparison.CurrentCultureIgnoreCase);
#else
                if (!line.EndsWith("found", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var foundIndex = line.LastIndexOf(" FOUND", StringComparison.OrdinalIgnoreCase);
#endif
                if (foundIndex <= 0)
                {
                    continue;
                }

                var filePart = line.Substring(0, foundIndex);
                var colonIndex = filePart.LastIndexOf(':');
                
                if (colonIndex < 0)
                {
                    continue;
                }

                var fileName = filePart.Substring(0, colonIndex).Trim();
                var virusName = filePart.Substring(colonIndex + 1).Trim();
                
                infectedFiles.Add(new ClamScanInfectedFile
                {
                    FileName = fileName,
                    VirusName = virusName
                });
            }

            return new ReadOnlyCollection<ClamScanInfectedFile>(infectedFiles);
        }

        public override string ToString() => RawResult;
    }
}
