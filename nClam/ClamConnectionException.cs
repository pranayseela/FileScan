namespace nClam
{
    using System;

    /// <summary>
    /// Exception thrown when a connection to the ClamAV server cannot be established.
    /// </summary>
    public class ClamConnectionException : ClamException
    {
        /// <summary>
        /// Gets the server address that failed to connect.
        /// </summary>
        public string Server { get; }

        /// <summary>
        /// Gets the port that failed to connect.
        /// </summary>
        public int Port { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ClamConnectionException"/> class.
        /// </summary>
        /// <param name="server">The server address that failed to connect.</param>
        /// <param name="port">The port that failed to connect.</param>
        /// <param name="innerException">The inner exception.</param>
        public ClamConnectionException(string server, int port, Exception innerException)
            : base($"Failed to connect to ClamAV server at {server}:{port}. See inner exception for details.", innerException)
        {
            Server = server;
            Port = port;
        }
    }
}
