using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace ConsoleApp
{
    class SecurityEncryptor
    {

        private static byte[] getSalt()
        {
            byte[] salt = new byte[32];

            var rand = new RNGCryptoServiceProvider();

            rand.GetNonZeroBytes(salt);

            return salt;
        }
        public void fileEncryptor(string inputFile, string password)
        {
            FileStream fs = new FileStream(inputFile + "aes", FileMode.Create);

            byte[] passByte = Encoding.UTF8.GetBytes(password);

            Rijndael AES = new RijndaelManaged();

            AES.KeySize = 256;
            AES.BlockSize = 128;

            AES.Padding = PaddingMode.PKCS7;

            byte[] salt = getSalt();

            var key = new Rfc2898DeriveBytes(passByte,salt, 50000);

            AES.Key = key.GetBytes(AES.KeySize/8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            AES.Mode = CipherMode.CFB;

            fs.Write(salt,0,salt.Length);

            CryptoStream cS = new CryptoStream(fs, AES.CreateEncryptor(AES.Key,AES.IV), CryptoStreamMode.Write);

            FileStream fsInput = new FileStream(inputFile + ".txt", FileMode.Open);

            byte[] buffer = new byte[1048576];
            int read;

            try
            {
                while((read = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cS.Write(buffer, 0, read);
                }

                fsInput.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
            finally
            {
                Console.WriteLine("File {0} has encrypt!", inputFile);
                cS.Close();
                fs.Close();
            }
        }

        public void fileDecryptor(string inputFile, string outputFile, string password)
        {
            byte[] passByte = Encoding.UTF8.GetBytes(password);
            byte[] salt = new byte[32];

            FileStream fs = new FileStream(inputFile, FileMode.Open);
            fs.Read(salt, 0, salt.Length);

            Rijndael AES = new RijndaelManaged();

            AES.KeySize = 256;
            AES.BlockSize = 128;

            var key = new Rfc2898DeriveBytes(passByte, salt, 50000);

            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CFB;

            CryptoStream cS = new CryptoStream(fs, AES.CreateDecryptor(), CryptoStreamMode.Read);

            FileStream fsOutput = new FileStream(outputFile + ".txt", FileMode.Create);

            byte[] buffer = new byte[1048576];
            int read;

            try
            {
                while ((read = cS.Read(buffer, 0, buffer.Length)) > 0)
                {
                    fsOutput.Write(buffer, 0, read);
                }
            }
            catch (CryptographicException ex_CryptoException)
            {
                Console.WriteLine("Something wrong! " + ex_CryptoException);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Something wrong! " + ex.Message);
            }

            try
            {
                cS.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Something wrong! " + ex.Message);
            }
            finally
            {
                Console.WriteLine("File {0} has decrypt!", inputFile);
                fsOutput.Close();
                fs.Close();
            }
        }
    }
    class Program
    {
        static void Main(string[] args)
        {
            SecurityEncryptor sE = new SecurityEncryptor();

            Console.Write("Enter name file: ");

            string nameFile = Console.ReadLine();

            Console.Write("Enter password: ");

            string password = Console.ReadLine();

            sE.fileEncryptor(nameFile,password);

            Console.WriteLine("////////////////////////////////////////////////////////////////");

            Console.Write("Enter name encrypt file: ");

            string nameCryptFile = Console.ReadLine();

            Console.Write("Enter name file decryption: ");

            string nameOutputFile = Console.ReadLine();

            Console.Write("Enter password: ");

            password = Console.ReadLine();

            sE.fileDecryptor(nameCryptFile,nameOutputFile,password);

        }
    }
}
