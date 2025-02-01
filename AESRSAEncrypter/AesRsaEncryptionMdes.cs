using System.Security.Cryptography;

namespace AESRSAEncrypterCore;

public static class AesRsaEncryptionMdes
{
    // Encrypt data using RSA public key from .cer file
    public static byte[] EncryptDataWithCertificate(byte[] aesKey, string certificatePath)
    {
        // Step 1: Read the PEM file content

        // Step 1: Read the PEM file content
        string pemContent = File.ReadAllText(certificatePath);

        // Step 2: Remove PEM headers/footers
        string base64Key = pemContent
            .Replace("-----BEGIN PUBLIC KEY-----", "")
            .Replace("-----END PUBLIC KEY-----", "")
            .Replace("\n", "")
            .Replace("\r", "");

        // Step 3: Convert Base64 string to byte array
        byte[] publicKeyBytes = Convert.FromBase64String(base64Key);

        // Step 4: Import the public key into RSA
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _); // Import the public key
            // Encrypt aesKey using RSA public key
            byte[] encryptedData = rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);

            return encryptedData;
        }
    }

    // RSA Key Generation
    public static void GenerateRsaKeys(out string publicKey, out string privateKey)
    {
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
        {
            publicKey = Convert.ToBase64String(rsa.ExportCspBlob(false)); // Public Key
            privateKey = Convert.ToBase64String(rsa.ExportCspBlob(true)); // Private Key
        }
    }


    // Encrypt data using AES and encrypt AES key using RSA public key
    public static (byte[] encryptedData, byte[] encryptedAesKey, byte[] iv) EncryptData(string data,
        string publicKeyPath)
    {
        var iv = new byte[]
        {
            0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            //0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        };
        // Generate AES Key and IV
        using (Aes aes = Aes.Create())
        {
            aes.KeySize = 256; // AES Key size 256 bits
            //aes.KeySize = 128; // AES Key size 128 bits
            aes.GenerateKey();
            aes.GenerateIV();

            // Encrypt Data using AES
            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV); // aes.IV);
            byte[] encryptedData;

            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(data);
                    }

                    encryptedData = ms.ToArray();
                }
            }

            // Encrypt AES Key using RSA
            byte[] encryptedAesKey = EncryptDataWithCertificate(aes.Key, publicKeyPath);


            return (encryptedData, encryptedAesKey,
                    aes.IV
                );
            //aes.IV);
        }
    }

    // Decrypt the AES key using RSA private key and then decrypt the data using AES
    public static string DecryptData(byte[] encryptedData, byte[] encryptedAesKey, byte[] iv, string privateKey)
    {
        // Decrypt AES Key using RSA
        byte[] aesKey;
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            rsa.ImportCspBlob(Convert.FromBase64String(privateKey));
            aesKey = rsa.Decrypt(encryptedAesKey, false); // RSA Decryption of AES Key
        }

        // Decrypt Data using AES
        using (Aes aes = Aes.Create())
        {
            aes.Key = aesKey;
            aes.IV = iv;

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using (var ms = new System.IO.MemoryStream(encryptedData))
            {
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    using (var sr = new System.IO.StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
        }
    }
}