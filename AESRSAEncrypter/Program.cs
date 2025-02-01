// See https://aka.ms/new-console-template for more information

//string publicKey, privateKey;
//AesRsaEncryption.GenerateRsaKeys(out publicKey, out privateKey);

using AESRSAEncrypterCore;

//string dataToEncrypt = "5267501320031267";//"5409484020362598";
// string dataToEncrypt = @"{""token"": ""5267501320031267"",""expiryMonth"": ""11"",""expiryYear"": ""29""}";
//string dataToEncrypt = @"{""tokenData"":{""token"":""516362******8954"",""expiryMonth"":""02"",""expiryYear"":""28"",""sequenceNumber"":""00""}}";

//string dataToEncrypt = @"{""tokenData"":{""token"":""516362******2222"",""expiryMonth"":""02"",""expiryYear"":""28"",""sequenceNumber"":""00""}}";
string dataToEncrypt = @"{""token"":""516362******2222"",""expiryMonth"":""02"",""expiryYear"":""28"",""sequenceNumber"":""00""}";

//string dataToEncrypt = "ciao sono Alessandro";
Console.WriteLine("Original Data: " + dataToEncrypt);
            
            

// Encrypt data using AES and RSA
string publicKeyPathPub = @"C:\PrivateRepos\Playground\AESRSAEncrypterCore\mdes-public_key.pub";
var (encryptedData, encryptedAesKey, iv) = AesRsaEncryptionMdes.EncryptData(dataToEncrypt, publicKeyPathPub);

// Decrypt the data
// string decryptedData = AesRsaEncryption.DecryptData(encryptedData, encryptedAesKey, iv, privateKey);

Console.WriteLine("encryptedData: " + Convert.ToHexString(encryptedData));
Console.WriteLine("encryptedAesKey: " + Convert.ToHexString(encryptedAesKey));
Console.WriteLine("iv: " + Convert.ToHexString(iv));