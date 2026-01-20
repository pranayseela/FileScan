# nClam

[![Build status](https://ci.appveyor.com/api/projects/status/bka4oktv8aw3r985?svg=true)](https://ci.appveyor.com/project/tekmaven/nclam)
[![NuGet version](https://badge.fury.io/nu/nClam.svg)](https://badge.fury.io/nu/nClam)

nClam is a lightweight .NET library for communicating with a ClamAV server (clamd) to perform virus scanning. It provides a simple, async API that encapsulates the communication protocol and parses scan results.

## Features

- ✅ Full async/await support
- ✅ Multiple scanning methods (server-side, stream-based, multithreaded, all-match)
- ✅ Comprehensive error handling and input validation
- ✅ Supports .NET 8.0, .NET 6.0, .NET Standard 2.0, and .NET Framework 4.5
- ✅ Well-documented API with XML documentation
- ✅ Thread-safe operations
- ✅ Server statistics and health monitoring
- ✅ Database reload without server restart
- ✅ Configurable connection and read/write timeouts
- ✅ Memory-efficient streaming with ArrayPool
- ✅ IDisposable and IAsyncDisposable support for proper resource management
- ✅ Enhanced error handling with specific exception types
- ✅ Optimized parsing with modern C# features
- ✅ Connection error handling with detailed exceptions

## Requirements

- **ClamAV Server (clamd)**: A running ClamAV daemon server
  - Windows: [ClamAV Win32 ports](http://oss.netfarm.it/clamav/)
  - Linux: Available through package managers (`apt-get install clamav-daemon` or `yum install clamav`)
  - macOS: `brew install clamav`

## Installation

Install the package via NuGet:

```bash
Install-Package nClam
```

Or via .NET CLI:

```bash
dotnet add package nClam
```

## Quick Start

```csharp
using System;
using System.Linq;
using System.Threading.Tasks;
using nClam;

class Program
{
    static async Task Main(string[] args)
    {
        var client = new ClamClient("localhost", 3310);
        
        // Check server connectivity
        var isConnected = await client.PingAsync();
        if (!isConnected)
        {
            Console.WriteLine("Failed to connect to ClamAV server");
            return;
        }
        
        // Scan a file
        var result = await client.SendAndScanFileAsync("C:\\test.txt");
        
        switch (result.Result)
        {
            case ClamScanResults.Clean:
                Console.WriteLine("File is clean!");
                break;
            case ClamScanResults.VirusDetected:
                Console.WriteLine("Virus detected!");
                foreach (var infectedFile in result.InfectedFiles)
                {
                    Console.WriteLine($"File: {infectedFile.FileName}");
                    Console.WriteLine($"Virus: {infectedFile.VirusName}");
                }
                break;
            case ClamScanResults.Error:
                Console.WriteLine($"Error: {result.RawResult}");
                break;
        }
    }
}
```

## API Reference

### Creating a Client

```csharp
// Default port is 3310
var client = new ClamClient("localhost");

// Or specify a custom port
var client = new ClamClient("clamav.example.com", 3310);
```

### Configuration

```csharp
// Configure chunk size for streaming (default: 128KB)
client.MaxChunkSize = 131072;

// Configure maximum stream size (default: 25MB)
client.MaxStreamSize = 26214400;

// Configure timeouts (default: 30s connection, 5min read/write)
client.ConnectionTimeout = 30000;  // 30 seconds
client.ReadWriteTimeout = 300000; // 5 minutes
```

### Server Information

```csharp
// Check if server is reachable
bool isAlive = await client.PingAsync();

// Get ClamAV server version
string version = await client.GetVersionAsync();
```

### Scanning Methods

#### 1. Scan File on Server

Scans a file that already exists on the ClamAV server's filesystem:

```csharp
var result = await client.ScanFileOnServerAsync("/path/to/file.txt");
```

#### 2. Send and Scan File

Sends file data to the server for scanning (recommended for remote files):

```csharp
// From file path
var result = await client.SendAndScanFileAsync("C:\\test.txt");

// From byte array
byte[] fileData = File.ReadAllBytes("test.txt");
var result = await client.SendAndScanFileAsync(fileData);

// From stream
using (var stream = File.OpenRead("test.txt"))
{
    var result = await client.SendAndScanFileAsync(stream);
}
```

#### 3. Multithreaded Scan

Uses multiple threads on the server for faster scanning of large directories:

```csharp
var result = await client.ScanFileOnServerMultithreadedAsync("/path/to/directory");
```

#### 4. Continue Scan (CONTSCAN)

Continues scanning after the first match is found:

```csharp
var result = await client.ContinueScanFileOnServerAsync("/path/to/directory");
```

#### 5. All Match Scan (ALLMATCHSCAN)

Scans and reports all matches found in a file:

```csharp
var result = await client.AllMatchScanFileOnServerAsync("/path/to/file.zip");
// Returns all viruses found, not just the first one
```

### Server Management

#### Get Statistics

Retrieve comprehensive statistics from the ClamAV server:

```csharp
var stats = await client.GetStatsAsync();
Console.WriteLine($"Threads: {stats.Threads}/{stats.MaxThreads}");
Console.WriteLine($"Scanned: {stats.ScannedItems}, Found: {stats.FoundItems}");
Console.WriteLine($"Virus Signatures: {stats.VirusSignatures}");
Console.WriteLine($"Memory Usage: {stats.MemoryUsage} bytes");
```

#### Reload Database

Reload the virus database without restarting the server:

```csharp
var success = await client.ReloadDatabaseAsync();
if (success)
{
    Console.WriteLine("Database reloaded successfully");
}
```

### Cancellation Support

All methods support cancellation tokens:

```csharp
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

var result = await client.SendAndScanFileAsync(
    "largefile.zip", 
    cts.Token
);
```

### Handling Results

```csharp
var result = await client.SendAndScanFileAsync("file.txt");

// Check scan status
if (result.Result == ClamScanResults.Clean)
{
    Console.WriteLine("File is safe");
}
else if (result.Result == ClamScanResults.VirusDetected)
{
    // Access infected files
    foreach (var infected in result.InfectedFiles)
    {
        Console.WriteLine($"Virus: {infected.VirusName} in {infected.FileName}");
    }
}
else if (result.Result == ClamScanResults.Error)
{
    // Check raw error message
    Console.WriteLine($"Error: {result.RawResult}");
}

// Access raw response
string rawResponse = result.RawResult;
```

## Complete Example

```csharp
using System;
using System.IO;
using System.Threading.Tasks;
using nClam;

class VirusScanner
{
    private readonly ClamClient _client;
    
    public VirusScanner(string server, int port = 3310)
    {
        _client = new ClamClient(server, port);
    }
    
    public async Task<bool> ScanFileAsync(string filePath)
    {
        try
        {
            // Verify server is available
            if (!await _client.PingAsync())
            {
                Console.WriteLine("ClamAV server is not available");
                return false;
            }
            
            // Scan the file
            var result = await _client.SendAndScanFileAsync(filePath);
            
            if (result.Result == ClamScanResults.VirusDetected)
            {
                Console.WriteLine($"⚠️  Virus detected in {filePath}");
                foreach (var infected in result.InfectedFiles)
                {
                    Console.WriteLine($"   - {infected.VirusName}");
                }
                return false;
            }
            else if (result.Result == ClamScanResults.Clean)
            {
                Console.WriteLine($"✓ File is clean: {filePath}");
                return true;
            }
            else
            {
                Console.WriteLine($"✗ Scan error: {result.RawResult}");
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error scanning file: {ex.Message}");
            return false;
        }
    }
}

// Usage
class Program
{
    static async Task Main(string[] args)
    {
        var scanner = new VirusScanner("localhost", 3310);
        await scanner.ScanFileAsync("test.txt");
    }
}
```

## Error Handling

The library provides comprehensive error handling with specific exception types:

### Input Validation

```csharp
try
{
    var client = new ClamClient(null, 3310); // Throws ArgumentException
}
catch (ArgumentException ex)
{
    Console.WriteLine(ex.Message);
}

try
{
    await client.SendAndScanFileAsync((byte[])null); // Throws ArgumentNullException
}
catch (ArgumentNullException ex)
{
    Console.WriteLine(ex.Message);
}
```

### Connection Errors

```csharp
try
{
    var result = await client.ScanFileOnServerAsync("/path/to/file");
}
catch (ClamConnectionException ex)
{
    Console.WriteLine($"Failed to connect to {ex.Server}:{ex.Port}");
    Console.WriteLine($"Inner exception: {ex.InnerException?.Message}");
}
catch (TimeoutException ex)
{
    Console.WriteLine($"Connection timed out: {ex.Message}");
}
```

### Stream Size Limits

```csharp
try
{
    await client.SendAndScanFileAsync(largeStream);
}
catch (MaxStreamSizeExceededException ex)
{
    Console.WriteLine($"File exceeds maximum size: {ex.Message}");
}
```

### Exception Hierarchy

- `ClamException` - Base exception for all ClamAV-related errors
- `ClamConnectionException` - Thrown when connection to server fails
- `MaxStreamSizeExceededException` - Thrown when file exceeds maximum stream size
- `TimeoutException` - Thrown when connection or operation times out

## Target Frameworks

- **.NET 8.0**: Latest LTS version with best performance
- **.NET 6.0**: LTS version with modern features
- **.NET Standard 2.0**: Compatible with .NET Core 2.0+, .NET Framework 4.6.1+, and more
- **.NET Framework 4.5**: For legacy applications

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. We appreciate contributions that:

- Fix bugs
- Add new features
- Improve documentation
- Add tests
- Improve code quality

## Links

- [NuGet Package](https://www.nuget.org/packages/nClam/)
- [ClamAV Official Website](https://www.clamav.net/)
- [ClamAV Documentation](https://docs.clamav.net/)
