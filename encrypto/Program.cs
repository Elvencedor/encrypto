using static System.Console;
using System;
using System.Security.Cryptography;
using cryptolib;

namespace encrypto
{
    class Program
    {
        static void Main(string[] args)
        {
            WriteLine("Enter a message you want to ecrypt: ");
            string message = ReadLine();
            WriteLine("Enter a password: ");
            string password = ReadLine();

            string cryptoText = protector.Encrypt(message, password);
            WriteLine($"Encrypted test => {cryptoText}");
            WriteLine("Enter password: ");
            string password2 = ReadLine();

            try
            {
                string clearText = protector.Decrypt(cryptoText, password2);
                WriteLine($"Decrypted text => {clearText}");
            }
            catch (CryptographicException ex)
            {
                
                WriteLine("{0}\n more details: {1}", "you entered a wrong password", ex.Message);
            }
            catch (Exception ex) {
                WriteLine("Unexpected error : \n{0} \n {1}", ex.GetType().Name, ex.Message);
            }

            WriteLine("Enter username of new user to register: ");
            string username = ReadLine();
            WriteLine("Enter password: ");
            string newPassword = ReadLine();

            var user = protector.Register(username, newPassword);
            WriteLine($"Username is {0}", user.Name);
            WriteLine($"Salt is {0}", user.Salt);
            WriteLine($"Password (salted and hashed) is {0}", user.SaltedHashedPassword);
            WriteLine();

            bool isPasswordCorrect = false;
            while(!isPasswordCorrect) {
                Write("Enter username: ");
                string login = ReadLine();
                WriteLine("Enter password: ");
                string loginPassword = ReadLine();

                isPasswordCorrect = protector.CheckPassword(login, loginPassword);

                if (isPasswordCorrect) {
                    WriteLine($"Success, user: {login} is logged in!");
                } else {
                    WriteLine("Invalid credentials, try again!");
                }
            }
        }
    }
}
