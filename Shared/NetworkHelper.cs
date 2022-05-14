using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Shared
{

    public static class NetworkHelper
    {
        public static async Task<string> ReadMessage(SslStream sslStream)
        {
            var byteLengthReceiveBuffer = new byte[sizeof(int)];

            //read the bytes to receive
            await sslStream.ReadAsync(byteLengthReceiveBuffer, 0, sizeof(int));

            var bytesToRead = BitConverter.ToInt32(byteLengthReceiveBuffer);
            var messageBuffer = new byte[bytesToRead];

            await sslStream.ReadAsync(messageBuffer, 0, bytesToRead);
            return BitConverter.ToString(messageBuffer).Replace("-", "");
        }

        public static async Task SendMessage(SslStream sslStream, X509Certificate2 certificate)
        {
            var messageBytes = certificate.GetCertHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
            var messageLengthBytes = BitConverter.GetBytes(messageBytes.Length);

            await sslStream.WriteAsync(messageLengthBytes, 0, messageLengthBytes.Length);
            await sslStream.WriteAsync(messageBytes);
        }

        public static bool ValidateServerCertificate(
          object sender,
          X509Certificate certificate,
          X509Chain chain,
          SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None || sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }
    }
}