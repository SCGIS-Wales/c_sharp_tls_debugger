using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace MTLSExample
{
    class Program
    {
        static async Task Main(string[] args)
        {
            if (args.Length != 6)
            {
                Console.WriteLine("Usage: MTLSExample <https_endpoint> <pfx_path> <pfx_passphrase> <tls_version> <cipher_suite> <ca_chain_path>");
                return;
            }

            string httpsEndpoint = args[0];
            string pfxPath = args[1];
            string pfxPassphrase = args[2];
            string tlsVersion = args[3];
            string cipherSuite = args[4];
            string caChainPath = args[5];

            try
            {
                // Set the TLS version
                ServicePointManager.SecurityProtocol = GetSecurityProtocol(tlsVersion);

                // Set the supported cipher suites (this is more complex in .NET Framework, may need to use Schannel registry settings)
                // Note: Setting cipher suites directly from code is not supported in .NET Framework.
                // This would typically be done via operating system settings.

                X509Certificate2 clientCertificate = new X509Certificate2(pfxPath, pfxPassphrase);
                X509Certificate2Collection caCertificates = LoadCaCertificates(caChainPath);

                using (HttpClientHandler handler = new HttpClientHandler())
                {
                    handler.ClientCertificates.Add(clientCertificate);
                    handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
                    {
                        chain.ChainPolicy.ExtraStore.AddRange(caCertificates);
                        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        
                        bool isValid = chain.Build((X509Certificate2)cert);
                        
                        if (!isValid)
                        {
                            Console.WriteLine("Server certificate validation failed:");
                            foreach (X509ChainStatus chainStatus in chain.ChainStatus)
                            {
                                Console.WriteLine(chainStatus.StatusInformation);
                            }
                        }
                        
                        return isValid;
                    };

                    using (HttpClient client = new HttpClient(handler))
                    {
                        HttpResponseMessage response = await client.GetAsync(httpsEndpoint);
                        response.EnsureSuccessStatusCode();
                        string responseBody = await response.Content.ReadAsStringAsync();
                        Console.WriteLine("Response received successfully:");
                        Console.WriteLine(responseBody);
                    }
                }
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("HTTP Request Exception: " + e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner Exception: " + e.InnerException.Message);
                }
                HandleTlsAlertCodes(e.InnerException);
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Authentication Exception: " + e.Message);
                HandleTlsAlertCodes(e.InnerException);
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception: " + e.Message);
                HandleTlsAlertCodes(e);
            }
        }

        private static SecurityProtocolType GetSecurityProtocol(string tlsVersion)
        {
            switch (tlsVersion.ToUpper())
            {
                case "TLS1.1":
                    return SecurityProtocolType.Tls11;
                case "TLS1.2":
                    return SecurityProtocolType.Tls12;
                case "TLS1.3":
                    return (SecurityProtocolType)12288; // TLS1.3
                default:
                    throw new ArgumentException("Unsupported TLS version: " + tlsVersion);
            }
        }

        private static X509Certificate2Collection LoadCaCertificates(string caChainPath)
        {
            string pemContent = File.ReadAllText(caChainPath);
            X509Certificate2Collection caCertificates = new X509Certificate2Collection();

            foreach (string cert in SplitPemCertificates(pemContent))
            {
                caCertificates.Add(new X509Certificate2(Convert.FromBase64String(cert)));
            }

            return caCertificates;
        }

        private static string[] SplitPemCertificates(string pemContent)
        {
            string pattern = @"-----BEGIN CERTIFICATE-----\s*(?<cert>.*?)\s*-----END CERTIFICATE-----";
            MatchCollection matches = Regex.Matches(pemContent, pattern, RegexOptions.Singleline);
            string[] certs = new string[matches.Count];
            for (int i = 0; i < matches.Count; i++)
            {
                certs[i] = matches[i].Groups["cert"].Value.Replace("\r", "").Replace("\n", "").Replace(" ", "");
            }

            return certs;
        }

        private static bool ValidateServerCertificate(HttpRequestMessage sender, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                return true;
            }

            Console.WriteLine("Server certificate validation failed:");
            Console.WriteLine(sslPolicyErrors);

            if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) != 0)
            {
                foreach (X509ChainStatus chainStatus in chain.ChainStatus)
                {
                    Console.WriteLine(chainStatus.StatusInformation);
                }
            }

            return false; // Certificate validation failed
        }

        private static void HandleTlsAlertCodes(Exception ex)
        {
            if (ex == null)
            {
                return;
            }

            string alertDescription = GetTlsAlertDescription(ex.Message);
            if (!string.IsNullOrEmpty(alertDescription))
            {
                Console.WriteLine("TLS Alert: " + alertDescription);
            }
        }

        private static string GetTlsAlertDescription(string message)
        {
            // This is a simplified example. Ideally, you would map the exact alert descriptions from the TLS specification.
            if (message.Contains("0"))
                return "Close Notify";
            if (message.Contains("10"))
                return "Unexpected Message";
            if (message.Contains("20"))
                return "Bad Record MAC";
            if (message.Contains("21"))
                return "Decryption Failed";
            if (message.Contains("22"))
                return "Record Overflow";
            if (message.Contains("30"))
                return "Decompression Failure";
            if (message.Contains("40"))
                return "Handshake Failure";
            if (message.Contains("42"))
                return "Bad Certificate";
            if (message.Contains("43"))
                return "Unsupported Certificate";
            if (message.Contains("44"))
                return "Certificate Revoked";
            if (message.Contains("45"))
                return "Certificate Expired";
            if (message.Contains("46"))
                return "Certificate Unknown";
            if (message.Contains("47"))
                return "Illegal Parameter";
            if (message.Contains("48"))
                return "Unknown CA";
            if (message.Contains("49"))
                return "Access Denied";
            if (message.Contains("50"))
                return "Decode Error";
            if (message.Contains("51"))
                return "Decrypt Error";
            if (message.Contains("60"))
                return "Export Restriction";
            if (message.Contains("70"))
                return "Protocol Version";
            if (message.Contains("71"))
                return "Insufficient Security";
            if (message.Contains("80"))
                return "Internal Error";
            if (message.Contains("86"))
                return "Inappropriate Fallback";
            if (message.Contains("90"))
                return "User Canceled";
            if (message.Contains("100"))
                return "No Renegotiation";
            if (message.Contains("110"))
                return "Unsupported Extension";
            if (message.Contains("112"))
                return "Unrecognized Name";
            if (message.Contains("113"))
                return "Bad Certificate Status Response";
            if (message.Contains("114"))
                return "Bad Certificate Hash Value";
            if (message.Contains("115"))
                return "Unknown PSK Identity";
            if (message.Contains("116"))
                return "Certificate Required";

            return null;
        }
    }
}
