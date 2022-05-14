using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using Shared;

var publicKey = new X509Certificate2(Path.Combine(Environment.CurrentDirectory, "server_cert.pem"));

var privateKeyText = await File.ReadAllTextAsync(Path.Combine(Environment.CurrentDirectory, "server_key.pem"));
var privateKeyBlocks = privateKeyText.Split("-", StringSplitOptions.RemoveEmptyEntries);
var privateKeyBytes = Convert.FromBase64String(privateKeyBlocks[1]);
using var rsa = RSA.Create();

if (privateKeyBlocks[0] == "BEGIN PRIVATE KEY")
    rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);
else if (privateKeyBlocks[0] == "BEGIN RSA PRIVATE KEY")
    rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

var keyPair = publicKey.CopyWithPrivateKey(rsa);
var serverCertificate = new X509Certificate2(keyPair.Export(X509ContentType.Pfx));

var listener = new TcpListener(IPAddress.Any, 1337);
listener.Start();

while (true)
{
    Console.WriteLine("Waiting for a client to connect");
    TcpClient tcpClient = await listener.AcceptTcpClientAsync();
    await ProcessClient(tcpClient);
}

async Task ProcessClient(TcpClient tcpClient)
{
    Console.WriteLine("Processing client...");
    SslStream sslStream = new(tcpClient.GetStream(), false, new RemoteCertificateValidationCallback(NetworkHelper.ValidateServerCertificate));
    await sslStream.AuthenticateAsServerAsync(serverCertificate, true, System.Security.Authentication.SslProtocols.Tls13, false);
    sslStream.ReadTimeout = 5000;
    sslStream.WriteTimeout = 5000;

    await NetworkHelper.SendMessage(sslStream, serverCertificate);
    var message = await NetworkHelper.ReadMessage(sslStream);
    Console.WriteLine($"Message from client {tcpClient.Client.RemoteEndPoint?.ToString()}: {message}");

    tcpClient.Close();
}