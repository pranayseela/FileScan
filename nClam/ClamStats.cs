namespace nClam
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Represents statistics from the ClamAV server.
    /// </summary>
    public class ClamStats
    {
        /// <summary>
        /// Gets the number of pools.
        /// </summary>
        public int Pools { get; private set; }

        /// <summary>
        /// Gets the state of the ClamAV daemon.
        /// </summary>
        public string State { get; private set; } = string.Empty;

        /// <summary>
        /// Gets the number of threads.
        /// </summary>
        public int Threads { get; private set; }

        /// <summary>
        /// Gets the maximum number of threads.
        /// </summary>
        public int MaxThreads { get; private set; }

        /// <summary>
        /// Gets the number of idle threads.
        /// </summary>
        public int IdleThreads { get; private set; }

        /// <summary>
        /// Gets the queue size.
        /// </summary>
        public int QueueSize { get; private set; }

        /// <summary>
        /// Gets the maximum queue size.
        /// </summary>
        public int MaxQueueSize { get; private set; }

        /// <summary>
        /// Gets the number of scanned items.
        /// </summary>
        public long ScannedItems { get; private set; }

        /// <summary>
        /// Gets the number of found items (viruses detected).
        /// </summary>
        public long FoundItems { get; private set; }

        /// <summary>
        /// Gets the memory usage in bytes.
        /// </summary>
        public long MemoryUsage { get; private set; }

        /// <summary>
        /// Gets the number of virus signatures loaded.
        /// </summary>
        public long VirusSignatures { get; private set; }

        /// <summary>
        /// Gets the time of the last database update.
        /// </summary>
        public DateTime? LastDatabaseUpdate { get; private set; }

        /// <summary>
        /// Gets additional raw statistics that weren't parsed.
        /// </summary>
        public Dictionary<string, string> AdditionalStats { get; private set; }

        internal ClamStats(string? rawStats)
        {
            AdditionalStats = new Dictionary<string, string>();
            if (rawStats != null)
            {
                ParseStats(rawStats);
            }
        }

        private void ParseStats(string rawStats)
        {
            if (string.IsNullOrWhiteSpace(rawStats))
            {
                return;
            }

            var lines = rawStats.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var line in lines)
            {
                var parts = line.Split(new[] { ':' }, 2, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length != 2)
                {
                    continue;
                }

                var key = parts[0].Trim();
                var value = parts[1].Trim();

                switch (key.ToUpperInvariant())
                {
                    case "POOLS":
                        if (int.TryParse(value, out var pools))
                            Pools = pools;
                        break;
                    case "STATE":
                        State = value;
                        break;
                    case "THREADS":
                        if (int.TryParse(value, out var threads))
                            Threads = threads;
                        break;
                    case "MAXTHREADS":
                        if (int.TryParse(value, out var maxThreads))
                            MaxThreads = maxThreads;
                        break;
                    case "IDLETHREADS":
                        if (int.TryParse(value, out var idleThreads))
                            IdleThreads = idleThreads;
                        break;
                    case "QUEUESIZE":
                        if (int.TryParse(value, out var queueSize))
                            QueueSize = queueSize;
                        break;
                    case "MAXQUEUESIZE":
                        if (int.TryParse(value, out var maxQueueSize))
                            MaxQueueSize = maxQueueSize;
                        break;
                    case "SCANNED":
                        if (long.TryParse(value, out var scanned))
                            ScannedItems = scanned;
                        break;
                    case "FOUND":
                        if (long.TryParse(value, out var found))
                            FoundItems = found;
                        break;
                    case "MEMUSAGE":
                        if (long.TryParse(value, out var memUsage))
                            MemoryUsage = memUsage;
                        break;
                    case "VIRUSES":
                        if (long.TryParse(value, out var viruses))
                            VirusSignatures = viruses;
                        break;
                    default:
                        AdditionalStats[key] = value;
                        break;
                }
            }
        }

        /// <summary>
        /// Returns a string representation of the statistics.
        /// </summary>
        public override string ToString()
        {
            return $"State: {State}, Threads: {Threads}/{MaxThreads}, Queue: {QueueSize}/{MaxQueueSize}, Scanned: {ScannedItems}, Found: {FoundItems}";
        }
    }
}
