using static System.Console;
using System;
using System.Security.Cryptography;
using cryptolib;

namespace signingDatawithSHA256
{
    class Program
    {
        static void Main(string[] args)
        {
            WriteLine("Enter any text to sign: ");
            string data = ReadLine();
            var signature = protector.GenerateSignature(data);
            WriteLine($"Signature: {signature}\n");
            WriteLine($"Public key used to check signature: \n {protector.publicKey}");

            if (protector.ValidateSignature(data, signature)) {
                WriteLine("\nSignature valid");
            } else {
                WriteLine("Invalid signature!");
            }
        }
    }
}
