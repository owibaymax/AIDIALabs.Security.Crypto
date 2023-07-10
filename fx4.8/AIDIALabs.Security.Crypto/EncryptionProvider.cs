using System;
using System.Security.Cryptography;
using System.Text;

namespace AIDIALabs.Security.Crypto
{
    public class EncryptionProvider
    {
        public static string SHA256Encrypt(string value, string salt, SaltType type)
        {
            string result = string.Empty;
            switch (type)
            {
                case SaltType.Before:
                    {
                        string text2 = CreateSalt(salt);
                        string s = value + text2;
                        UTF8Encoding uTF8Encoding2 = new UTF8Encoding();
                        SHA256Managed sHA256Managed2 = new SHA256Managed();
                        byte[] inputArray2 = sHA256Managed2.ComputeHash(uTF8Encoding2.GetBytes(s));
                        result = ByteArrayToString(inputArray2);
                        break;
                    }
                case SaltType.After:
                    {
                        string text = CreateSalt(salt);
                        UTF8Encoding uTF8Encoding = new UTF8Encoding();
                        SHA256Managed sHA256Managed = new SHA256Managed();
                        byte[] inputArray = sHA256Managed.ComputeHash(uTF8Encoding.GetBytes(value));
                        result = ByteArrayToString(inputArray) + text;
                        break;
                    }
                case SaltType.Both:
                    result = SHA256Encrypt(value, salt);
                    break;
            }
            return result;
        }

        public static string SHA256Encrypt(string value, string salt)
        {
            string text = CreateSalt(salt);
            string s = value + text;
            UTF8Encoding uTF8Encoding = new UTF8Encoding();
            SHA256Managed sHA256Managed = new SHA256Managed();
            byte[] inputArray = sHA256Managed.ComputeHash(uTF8Encoding.GetBytes(s));
            return ByteArrayToString(inputArray) + text;
        }

        public static string SHA256Encrypt(string value)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(value);
            try
            {
                SHA256CryptoServiceProvider sHA256CryptoServiceProvider = new SHA256CryptoServiceProvider();
                return BitConverter.ToString(sHA256CryptoServiceProvider.ComputeHash(bytes)).Replace("-", "");
            }
            catch (Exception)
            {
                return "";
            }
        }

        public static string SHA1Encrypt(string value)
        {
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(value));
                var sb = new StringBuilder(hash.Length * 2);

                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("X2"));
                }

                return sb.ToString().ToUpper();
            }
        }

        public static string Encrypt(string Value, string key)
        {
            try
            {
                byte[] bytes = Encoding.ASCII.GetBytes(Value);
                TripleDESCryptoServiceProvider tripleDESCryptoServiceProvider = new TripleDESCryptoServiceProvider();
                tripleDESCryptoServiceProvider.KeySize = 128;
                tripleDESCryptoServiceProvider.Key = ConvertHextoByte(key);
                tripleDESCryptoServiceProvider.Mode = CipherMode.ECB;
                tripleDESCryptoServiceProvider.Padding = PaddingMode.Zeros;
                byte[] abValue = tripleDESCryptoServiceProvider.CreateEncryptor().TransformFinalBlock(bytes, 0, bytes.Length);
                return ConvertToHex(abValue);
            }
            catch
            {
                return "";
            }
        }

        public static string Decrypt(string hex, string key)
        {
            try
            {
                byte[] array = ConvertHextoByte(hex);
                TripleDESCryptoServiceProvider tripleDESCryptoServiceProvider = new TripleDESCryptoServiceProvider();
                tripleDESCryptoServiceProvider.KeySize = 128;
                tripleDESCryptoServiceProvider.Key = ConvertHextoByte(key);
                tripleDESCryptoServiceProvider.Mode = CipherMode.ECB;
                tripleDESCryptoServiceProvider.Padding = PaddingMode.Zeros;
                byte[] bytes = tripleDESCryptoServiceProvider.CreateDecryptor().TransformFinalBlock(array, 0, array.Length);
                return Encoding.ASCII.GetString(bytes).Replace("\0", "");
            }
            catch
            {
                return "";
            }
        }

        private static string ConvertToHex(byte[] abValue)
        {
            string text = "";
            try
            {
                text = BitConverter.ToString(abValue, 0, abValue.Length);
                return text.Replace("-", "");
            }
            catch
            {
                return "";
            }
        }

        private static byte[] ConvertHextoByte(string strHex)
        {
            if (strHex != null)
            {
                byte[] array = new byte[strHex.Length / 2];
                try
                {
                    for (int i = 0; i < strHex.Length / 2; i++)
                    {
                        array[i] = Convert.ToByte(strHex.Substring(i * 2, 2), 16);
                    }
                    return array;
                }
                catch
                {
                    return array;
                }
            }
            return new byte[1];
        }

        private static string ByteArrayToString(byte[] inputArray)
        {
            StringBuilder stringBuilder = new StringBuilder("");
            for (int i = 0; i < inputArray.Length; i++)
            {
                stringBuilder.Append(inputArray[i].ToString("X2"));
            }
            return stringBuilder.ToString();
        }

        private static string CreateSalt(string UserName)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(UserName);
            long num = 0L;
            byte[] array = bytes;
            foreach (int num2 in array)
            {
                num ^= num2;
            }
            Random random = new Random(Convert.ToInt32(num));
            string text = random.Next().ToString();
            text += random.Next();
            text += random.Next();
            return text + random.Next();
        }
    }
}
