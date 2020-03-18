using System;
using System.Collections;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;


namespace Certificates
{
    class Program
    {
        static void Main(string[] args)
        {
            string teststring = "Dieser String wird signiert";
            X509Certificate2 cert = new X509Certificate2(File.ReadAllBytes(@"C:\Users\rapha\Documents\SWP1\WU\gorbach2-test-cert.pfx"), "1234");
            X509Certificate2 certpub = new X509Certificate2(File.ReadAllBytes(@"C:\Users\rapha\Documents\SWP1\WU\gorbach2-test-cert-public.pem"));
            

            RSACng rSAprivate = (RSACng)cert.GetRSAPrivateKey();
            RSACng rSApublic = (RSACng)certpub.GetRSAPublicKey();

           

            ValueTuple<byte[], byte[]> tuple;

            tuple = ComputeandSignHash(teststring);



            ReadHash(tuple.Item1, tuple.Item2);

            
           


            (byte[], byte[]) ComputeandSignHash(string RawData)
            {
                SHA256 sha256Hash = SHA256.Create();

                byte[] hash = sha256Hash.ComputeHash(UnicodeEncoding.Unicode.GetBytes(RawData));
              
                return (hash, rSAprivate.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

            }

           

            void ReadHash(byte[] hash, byte[] signature)
            {
  
                bool ok = rSAprivate.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                Console.WriteLine(ok);
                
            }

     
        }
    }
}
