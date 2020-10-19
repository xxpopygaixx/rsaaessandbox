using System;
using System.Security.Cryptography;
using System.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;

namespace RsaAesSanbox
{
    class PwdStore : IPasswordFinder
    {
        private char[] password;

        public PwdStore(char[] password)
        {
            this.password = password;
        }

        public char[] GetPassword()
        {
            return (char[])password.Clone();
        }
    }
    class Program
    {
        static void Main(string[] args)
        {
            StreamReader sr = new StreamReader(@"1.txt");

            IPasswordFinder pFinder = new PwdStore(File.ReadAllText(@"pwd.txt").ToCharArray());

            PemReader pr = new PemReader(sr,pFinder);
            AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            RSAParameters param = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);
            
            var csp = RSA.Create(param);

            var aeskey = Convert.FromBase64String(File.ReadAllText(@"aesKey.txt"));
            var aesIV = Convert.FromBase64String(File.ReadAllText(@"aesIV.txt"));

            var decryptkey = csp.Decrypt(aeskey, RSAEncryptionPadding.Pkcs1);
            var decryptIV = csp.Decrypt(aesIV, RSAEncryptionPadding.Pkcs1);

            var encmsg = Convert.FromBase64String(File.ReadAllText(@"encMsg.txt"));

            Aes aes = Aes.Create();
            aes.Key = decryptkey;
            aes.IV = decryptIV;

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream msDecrypt = new MemoryStream(encmsg))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        Console.WriteLine(srDecrypt.ReadToEnd());
                    }
                }
            }
        }
    }
}
