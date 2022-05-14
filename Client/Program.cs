using Shared;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;


var publicKey = new X509Certificate2(Path.Combine(Environment.CurrentDirectory, "client_cert.pem"));

var privateKeyText = await File.ReadAllTextAsync(Path.Combine(Environment.CurrentDirectory, "client_key.pem"));
var privateKeyBlocks = privateKeyText.Split("-", StringSplitOptions.RemoveEmptyEntries);
var privateKeyBytes = Convert.FromBase64String(privateKeyBlocks[1]);
using var rsa = RSA.Create();

if (privateKeyBlocks[0] == "BEGIN PRIVATE KEY")
    rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);
else if (privateKeyBlocks[0] == "BEGIN RSA PRIVATE KEY")
    rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

var keyPair = publicKey.CopyWithPrivateKey(rsa);
var clientCertificate = new X509Certificate2(keyPair.Export(X509ContentType.Pfx));

X509Certificate2Collection certificateCollection = new X509Certificate2Collection();
certificateCollection.Add(clientCertificate);

var tcpClient = new TcpClient();
await tcpClient.ConnectAsync("localhost", 1337);

SslStream sslStream = new(tcpClient.GetStream(), false, new RemoteCertificateValidationCallback(NetworkHelper.ValidateServerCertificate));
await sslStream.AuthenticateAsClientAsync("localhost", certificateCollection, System.Security.Authentication.SslProtocols.Tls13, false); 

sslStream.ReadTimeout = 5000;
sslStream.WriteTimeout = 5000;
await NetworkHelper.SendMessage(sslStream, clientCertificate);
var message = await NetworkHelper.ReadMessage(sslStream);
Console.WriteLine($"Message from server {tcpClient.Client.RemoteEndPoint?.ToString()}: {message}");

tcpClient.Close();
Console.WriteLine("Terminate in 5 sec...");
await Task.Delay(TimeSpan.FromSeconds(5));