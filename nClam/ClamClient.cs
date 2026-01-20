namespace nClam
{
    using System;
#if !NET45
    using System.Buffers;
#endif
    using System.IO;
    using System.Net.Sockets;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    public class ClamClient : IClamClient, IDisposable
#if !NET45 && !NETSTANDARD2_0
        , IAsyncDisposable
#endif
    {
        /// <summary>
        /// Maximum size (in bytes) which streams will be broken up to when sending to the ClamAV server.  Used in the SendAndScanFile methods.  128kb is the default size.
        /// </summary>
        public int MaxChunkSize { get; set; }

        /// <summary>
        /// Maximum size (in bytes) that can be streamed to the ClamAV server before it will terminate the connection. Used in the SendAndScanFile methods. 25mb is the default size.
        /// </summary>
        public long MaxStreamSize { get; set; }

        /// <summary>
        /// Address to the ClamAV server
        /// </summary>
        public string Server { get; set; }

        /// <summary>
        /// Port which the ClamAV server is listening on
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// Connection timeout in milliseconds. Default is 30 seconds (30000ms).
        /// </summary>
        public int ConnectionTimeout { get; set; }

        /// <summary>
        /// Read/Write timeout in milliseconds. Default is 5 minutes (300000ms).
        /// </summary>
        public int ReadWriteTimeout { get; set; }

        private bool _disposed = false;

        /// <summary>
        /// A class to connect to a ClamAV server and request virus scans
        /// </summary>
        /// <param name="server">Address to the ClamAV server</param>
        /// <param name="port">Port which the ClamAV server is listening on</param>
        /// <exception cref="ArgumentException">Thrown when <paramref name="server"/> is null or empty.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="port"/> is not in the valid range (1-65535).</exception>
        public ClamClient(string server, int port = 3310)
        {
            if (string.IsNullOrWhiteSpace(server))
            {
                throw new ArgumentException("Server address cannot be null or empty.", nameof(server));
            }

            if (port <= 0 || port > 65535)
            {
                throw new ArgumentOutOfRangeException(nameof(port), "Port must be between 1 and 65535.");
            }

            MaxChunkSize = 131_072; // 128KB
            MaxStreamSize = 26_214_400; // 25MB
            Server = server;
            Port = port;
            ConnectionTimeout = 30_000; // 30 seconds
            ReadWriteTimeout = 300_000; // 5 minutes
        }

        /// <summary>
        /// Helper method which connects to the ClamAV Server, performs the command and returns the result.
        /// </summary>
        /// <param name="command">The command to execute on the ClamAV Server</param>
        /// <param name="cancellationToken">cancellation token used in requests</param>
        /// <param name="additionalCommand">Action to define additional server communications.  Executed after the command is sent and before the response is read.</param>
        /// <returns>The full response from the ClamAV server.</returns>
        private async Task<string> ExecuteClamCommandAsync(string command, CancellationToken cancellationToken, Func<NetworkStream, CancellationToken, Task>? additionalCommand = null)
        {
#if DEBUG
            var stopWatch = System.Diagnostics.Stopwatch.StartNew();
#endif
            string result;

            using var clam = new TcpClient();
            clam.ReceiveTimeout = ReadWriteTimeout;
            clam.SendTimeout = ReadWriteTimeout;

            var connectTask = clam.ConnectAsync(Server, Port);
            var timeoutTask = Task.Delay(ConnectionTimeout, cancellationToken);

            try
            {
                var completedTask = await Task.WhenAny(connectTask, timeoutTask).ConfigureAwait(false);
                if (completedTask == timeoutTask)
                {
                    throw new TimeoutException($"Connection to {Server}:{Port} timed out after {ConnectionTimeout}ms");
                }

                await connectTask.ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not TimeoutException)
            {
                throw new ClamConnectionException(Server, Port, ex);
            }

            using var networkStream = clam.GetStream();
            networkStream.ReadTimeout = ReadWriteTimeout;
            networkStream.WriteTimeout = ReadWriteTimeout;
            
            var commandText = $"z{command}\0";
            var commandBytes = Encoding.UTF8.GetBytes(commandText);
#if NET6_0_OR_GREATER
            await networkStream.WriteAsync(commandBytes.AsMemory(), cancellationToken).ConfigureAwait(false);
#else
            await networkStream.WriteAsync(commandBytes, 0, commandBytes.Length, cancellationToken).ConfigureAwait(false);
#endif

            if (additionalCommand != null)
            {
                await additionalCommand(networkStream, cancellationToken).ConfigureAwait(false);
            }

            // Flush to ensure all data is sent
            await networkStream.FlushAsync(cancellationToken).ConfigureAwait(false);

            using var reader = new StreamReader(networkStream, Encoding.UTF8, true, 4096, leaveOpen: false);
            result = await reader.ReadToEndAsync().ConfigureAwait(false);

            if (!string.IsNullOrEmpty(result))
            {
                //if we have a result, trim off the terminating null character
                result = result.TrimEnd('\0');
            }
#if DEBUG
            stopWatch.Stop();
            System.Diagnostics.Debug.WriteLine("Command {0} took: {1}", command, stopWatch.Elapsed);
#endif
            return result;
        }

        /// <summary>
        /// Helper method to send a byte array over the wire to the ClamAV server, split up in chunks.
        /// </summary>
        /// <param name="sourceStream">The stream to send to the ClamAV server.</param>
        /// <param name="clamStream">The communication channel to the ClamAV server.</param>
        /// <param name="cancellationToken"></param>
        private async Task SendStreamFileChunksAsync(Stream sourceStream, Stream clamStream, CancellationToken cancellationToken)
        {
            var chunkSize = MaxChunkSize;
#if NET45
            var bytes = new byte[chunkSize];
#else
            var arrayPool = ArrayPool<byte>.Shared;
            var bytes = arrayPool.Rent(chunkSize);
#endif
            try
            {
                int bytesRead;
#if NET6_0_OR_GREATER
                while ((bytesRead = await sourceStream.ReadAsync(bytes.AsMemory(0, chunkSize), cancellationToken).ConfigureAwait(false)) > 0)
#else
                while ((bytesRead = await sourceStream.ReadAsync(bytes, 0, chunkSize, cancellationToken).ConfigureAwait(false)) > 0)
#endif
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (sourceStream.Position > MaxStreamSize)
                    {
                        throw new MaxStreamSizeExceededException(MaxStreamSize);
                    }

                    var sizeBytes = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(bytesRead));  //convert size to NetworkOrder!
#if NET6_0_OR_GREATER
                    await clamStream.WriteAsync(sizeBytes.AsMemory(), cancellationToken).ConfigureAwait(false);
                    await clamStream.WriteAsync(bytes.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
#else
                    await clamStream.WriteAsync(sizeBytes, 0, sizeBytes.Length, cancellationToken).ConfigureAwait(false);
                    await clamStream.WriteAsync(bytes, 0, bytesRead, cancellationToken).ConfigureAwait(false);
#endif
                }

                var newMessage = BitConverter.GetBytes(0);
#if NET6_0_OR_GREATER
                await clamStream.WriteAsync(newMessage.AsMemory(), cancellationToken).ConfigureAwait(false);
#else
                await clamStream.WriteAsync(newMessage, 0, newMessage.Length, cancellationToken).ConfigureAwait(false);
#endif
            }
            finally
            {
#if !NET45
                arrayPool.Return(bytes);
#endif
            }
        }

        /// <summary>
        /// Gets the ClamAV server version
        /// </summary>
        public Task<string> GetVersionAsync() => GetVersionAsync(CancellationToken.None);

        /// <summary>
        /// Gets the ClamAV server version
        /// </summary>
        public async Task<string> GetVersionAsync(CancellationToken cancellationToken)
        {
            var version = await ExecuteClamCommandAsync("VERSION", cancellationToken).ConfigureAwait(false);
            return version;
        }

        /// <summary>
        /// Executes a PING command on the ClamAV server.
        /// </summary>
        /// <returns>If the server responds with PONG, returns true.  Otherwise returns false.</returns>
        public Task<bool> PingAsync() => PingAsync(CancellationToken.None);

        /// <summary>
        /// Executes a PING command on the ClamAV server.
        /// </summary>
        /// <returns>If the server responds with PONG, returns true.  Otherwise returns false.</returns>
        public async Task<bool> PingAsync(CancellationToken cancellationToken)
        {
            var result = await ExecuteClamCommandAsync("PING", cancellationToken).ConfigureAwait(false);
            return result.Equals("pong", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Scans a file/directory on the ClamAV Server.
        /// </summary>
        /// <param name="filePath">Path to the file/directory on the ClamAV server.</param>
        public Task<ClamScanResult> ScanFileOnServerAsync(string filePath) => ScanFileOnServerAsync(filePath, CancellationToken.None);

        /// <summary>
        /// Scans a file/directory on the ClamAV Server.
        /// </summary>
        /// <param name="filePath">Path to the file/directory on the ClamAV server.</param>
        /// <param name="cancellationToken">cancellation token used for request</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the scan result.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="filePath"/> is null or empty.</exception>
        public async Task<ClamScanResult> ScanFileOnServerAsync(string filePath, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(filePath))
            {
                throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));
            }

            return new ClamScanResult(await ExecuteClamCommandAsync($"SCAN {filePath}", cancellationToken));
        }

        /// <summary>
        /// Scans a file/directory on the ClamAV Server using multiple threads on the server.
        /// </summary>
        /// <param name="filePath">Path to the file/directory on the ClamAV server.</param>
        public Task<ClamScanResult> ScanFileOnServerMultithreadedAsync(string filePath) => ScanFileOnServerMultithreadedAsync(filePath, CancellationToken.None);

        /// <summary>
        /// Scans a file/directory on the ClamAV Server using multiple threads on the server.
        /// </summary>
        /// <param name="filePath">Path to the file/directory on the ClamAV server.</param>
        /// <param name="cancellationToken">cancellation token used for request</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the scan result.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="filePath"/> is null or empty.</exception>
        public async Task<ClamScanResult> ScanFileOnServerMultithreadedAsync(string filePath, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(filePath))
            {
                throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));
            }

            return new ClamScanResult(await ExecuteClamCommandAsync($"MULTISCAN {filePath}", cancellationToken));
        }

        /// <summary>
        /// Sends the data to the ClamAV server as a stream.
        /// </summary>
        /// <param name="fileData">Byte array containing the data from a file.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the scan result.</returns>
        public Task<ClamScanResult> SendAndScanFileAsync(byte[] fileData) => SendAndScanFileAsync(fileData, CancellationToken.None);

        /// <summary>
        /// Sends the data to the ClamAV server as a stream.
        /// </summary>
        /// <param name="fileData">Byte array containing the data from a file.</param>
        /// <param name="cancellationToken">cancellation token used for request</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the scan result.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="fileData"/> is null.</exception>
        public async Task<ClamScanResult> SendAndScanFileAsync(byte[] fileData, CancellationToken cancellationToken)
        {
            if (fileData == null)
            {
                throw new ArgumentNullException(nameof(fileData));
            }

            using var sourceStream = new MemoryStream(fileData);
            return new ClamScanResult(await ExecuteClamCommandAsync("INSTREAM", cancellationToken, (stream, token) => SendStreamFileChunksAsync(sourceStream, stream, token)));
        }

        /// <summary>
        /// Sends the data to the ClamAV server as a stream.
        /// </summary>
        /// <param name="sourceStream">Stream containing the data to scan.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the scan result.</returns>
        public Task<ClamScanResult> SendAndScanFileAsync(Stream sourceStream) => SendAndScanFileAsync(sourceStream, CancellationToken.None);

        /// <summary>
        /// Sends the data to the ClamAV server as a stream.
        /// </summary>
        /// <param name="sourceStream">Stream containing the data to scan.</param>
        /// <param name="cancellationToken">cancellation token used for request</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the scan result.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="sourceStream"/> is null.</exception>
        public async Task<ClamScanResult> SendAndScanFileAsync(Stream sourceStream, CancellationToken cancellationToken)
        {
            if (sourceStream == null)
            {
                throw new ArgumentNullException(nameof(sourceStream));
            }

            return new ClamScanResult(await ExecuteClamCommandAsync("INSTREAM", cancellationToken, (stream, token) => SendStreamFileChunksAsync(sourceStream, stream, token)));
        }

        /// <summary>
        /// Reads the file from the path and then sends it to the ClamAV server as a stream.
        /// </summary>
        /// <param name="filePath">Path to the file/directory.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the scan result.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="filePath"/> is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the file specified by <paramref name="filePath"/> does not exist.</exception>
        public async Task<ClamScanResult> SendAndScanFileAsync(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
            {
                throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));
            }

            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"File not found: {filePath}", filePath);
            }

            using var stream = File.OpenRead(filePath);
            return await SendAndScanFileAsync(stream).ConfigureAwait(false);
        }

        /// <summary>
        /// Reads the file from the path and then sends it to the ClamAV server as a stream.
        /// </summary>
        /// <param name="filePath">Path to the file/directory.</param>
        /// <param name="cancellationToken">cancellation token used for request</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the scan result.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="filePath"/> is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the file specified by <paramref name="filePath"/> does not exist.</exception>
        public async Task<ClamScanResult> SendAndScanFileAsync(string filePath, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(filePath))
            {
                throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));
            }

            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"File not found: {filePath}", filePath);
            }

            using var stream = File.OpenRead(filePath);
            return await SendAndScanFileAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Scans a file/directory on the ClamAV Server and continues scanning after first match (CONTSCAN).
        /// </summary>
        /// <param name="filePath">Path to the file/directory on the ClamAV server.</param>
        public Task<ClamScanResult> ContinueScanFileOnServerAsync(string filePath) => ContinueScanFileOnServerAsync(filePath, CancellationToken.None);

        /// <summary>
        /// Scans a file/directory on the ClamAV Server and continues scanning after first match (CONTSCAN).
        /// </summary>
        /// <param name="filePath">Path to the file/directory on the ClamAV server.</param>
        /// <param name="cancellationToken">cancellation token used for request</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the scan result.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="filePath"/> is null or empty.</exception>
        public async Task<ClamScanResult> ContinueScanFileOnServerAsync(string filePath, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(filePath))
            {
                throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));
            }

            return new ClamScanResult(await ExecuteClamCommandAsync($"CONTSCAN {filePath}", cancellationToken));
        }

        /// <summary>
        /// Scans a file/directory and reports all matches found (ALLMATCHSCAN).
        /// </summary>
        /// <param name="filePath">Path to the file/directory on the ClamAV server.</param>
        public Task<ClamScanResult> AllMatchScanFileOnServerAsync(string filePath) => AllMatchScanFileOnServerAsync(filePath, CancellationToken.None);

        /// <summary>
        /// Scans a file/directory and reports all matches found (ALLMATCHSCAN).
        /// </summary>
        /// <param name="filePath">Path to the file/directory on the ClamAV server.</param>
        /// <param name="cancellationToken">cancellation token used for request</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the scan result.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="filePath"/> is null or empty.</exception>
        public async Task<ClamScanResult> AllMatchScanFileOnServerAsync(string filePath, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(filePath))
            {
                throw new ArgumentException("File path cannot be null or empty.", nameof(filePath));
            }

            return new ClamScanResult(await ExecuteClamCommandAsync($"ALLMATCHSCAN {filePath}", cancellationToken));
        }

        /// <summary>
        /// Gets statistics from the ClamAV server.
        /// </summary>
        public Task<ClamStats> GetStatsAsync() => GetStatsAsync(CancellationToken.None);

        /// <summary>
        /// Gets statistics from the ClamAV server.
        /// </summary>
        /// <param name="cancellationToken">cancellation token used for request</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the server statistics.</returns>
        public async Task<ClamStats> GetStatsAsync(CancellationToken cancellationToken)
        {
            var stats = await ExecuteClamCommandAsync("STATS", cancellationToken).ConfigureAwait(false);
            return new ClamStats(stats);
        }

        /// <summary>
        /// Reloads the virus database on the ClamAV server.
        /// </summary>
        public Task<bool> ReloadDatabaseAsync() => ReloadDatabaseAsync(CancellationToken.None);

        /// <summary>
        /// Reloads the virus database on the ClamAV server.
        /// </summary>
        /// <param name="cancellationToken">cancellation token used for request</param>
        /// <returns>A task that represents the asynchronous operation. Returns true if the reload was successful.</returns>
        public async Task<bool> ReloadDatabaseAsync(CancellationToken cancellationToken)
        {
            var result = await ExecuteClamCommandAsync("RELOAD", cancellationToken).ConfigureAwait(false);
#if NET45
            return result.ToLowerInvariant().Contains("reload") || result.ToLowerInvariant() == "ok";
#else
            return result.Contains("reload", StringComparison.OrdinalIgnoreCase) || result.Equals("ok", StringComparison.OrdinalIgnoreCase);
#endif
        }

        /// <summary>
        /// Releases all resources used by the ClamClient.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

#if !NET45 && !NETSTANDARD2_0
        /// <summary>
        /// Asynchronously releases all resources used by the ClamClient.
        /// </summary>
        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
#endif

        /// <summary>
        /// Releases the unmanaged resources used by the ClamClient and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">True to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose managed resources here if any
                }
                _disposed = true;
            }
        }
    }
}