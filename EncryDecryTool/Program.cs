// See https://aka.ms/new-console-template for more information
using System.Security.Cryptography;
using System.Text;

string keyStr = string.Empty;
string ivStr = string.Empty;


Console.WriteLine("請輸入key (長度為24):");
keyStr = Console.ReadLine();

Console.WriteLine("請輸入iv (長度為16):");
ivStr = Console.ReadLine();

byte[] key = Encoding.UTF8.GetBytes(keyStr);
byte[] iv = Encoding.UTF8.GetBytes(ivStr);

Console.WriteLine("要進行的操作為：1.加密 2.解碼");
string actionOption = Console.ReadLine();
if(actionOption == "1" || actionOption== "加密")
{
    Console.WriteLine("請輸入要進行加密的原始資料");
    string content = Console.ReadLine();

    Console.WriteLine();
    Console.WriteLine($"原始: {content}");
    
    var encrypted = Encrypt(content, key, iv);
    Console.WriteLine($"加密: {encrypted}");

}else if (actionOption == "2" || actionOption == "解碼")
{
    Console.WriteLine("請輸入要進行解碼的加密資料");
    string content = Console.ReadLine();

    Console.WriteLine();
    Console.WriteLine($"原始: {content}");

    var decrypted = Decrypt(content, key, iv);
    Console.WriteLine($"解碼: {decrypted}");
}
else
{
    Console.WriteLine("無法辨識指定的操作");
}

Console.ReadLine();


 static string Encrypt(string plainText, byte[] key, byte[] iv)
{
    return Convert.ToBase64String(EncryptStringToBytes(plainText, key, iv));
}

 static string Decrypt(string cipherText, byte[] key, byte[] iv)
{
    var encrypted = Convert.FromBase64String(cipherText);
    return DecryptStringFromBytes(encrypted, key, iv);
}

 static string DecryptStringFromBytes(byte[] cipherText, byte[] key, byte[] iv)
{
    // Check arguments.
    if (cipherText == null || cipherText.Length <= 0)
    {
        throw new ArgumentNullException("cipherText");
    }
    if (key == null || key.Length <= 0)
    {
        throw new ArgumentNullException("key");
    }
    if (iv == null || iv.Length <= 0)
    {
        throw new ArgumentNullException("key");
    }

    string plaintext = "";

    using (var aesAlg = Aes.Create())
    {

        aesAlg.Mode = CipherMode.CBC;
        aesAlg.Padding = PaddingMode.PKCS7;
        aesAlg.FeedbackSize = 128;

        aesAlg.Key = key;
        aesAlg.IV = iv;


        var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
        try
        {
            using (var msDecrypt = new MemoryStream(cipherText))
            {
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {

                    using (var srDecrypt = new StreamReader(csDecrypt))
                    {
                        plaintext = srDecrypt.ReadToEnd();

                    }

                }
            }
        }
        catch
        {
            plaintext = "keyError";
        }
    }

    return plaintext;
}


 static byte[] EncryptStringToBytes(string plainText, byte[] key, byte[] iv)
{
    // Check arguments.
    if (plainText == null || plainText.Length <= 0)
    {
        throw new ArgumentNullException("plainText");
    }
    if (key == null || key.Length <= 0)
    {
        throw new ArgumentNullException("key");
    }
    if (iv == null || iv.Length <= 0)
    {
        throw new ArgumentNullException("key");
    }
    byte[] encrypted;
    // Create a RijndaelManaged object
    // with the specified key and IV.
    using (var aesAlg = Aes.Create())
    {
        aesAlg.Mode = CipherMode.CBC;
        aesAlg.Padding = PaddingMode.PKCS7;
        aesAlg.FeedbackSize = 128;

        aesAlg.Key = key;
        aesAlg.IV = iv;

        // Create a decrytor to perform the stream transform.
        var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

        // Create the streams used for encryption.
        using (var msEncrypt = new MemoryStream())
        {
            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            {
                using (var swEncrypt = new StreamWriter(csEncrypt))
                {
                    //Write all data to the stream.
                    swEncrypt.Write(plainText);
                }
                encrypted = msEncrypt.ToArray();
            }
        }
    }

    // Return the encrypted bytes from the memory stream.
    return encrypted;
}
