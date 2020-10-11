using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Xml.Linq;
using static System.Convert;

namespace cryptolib
{
    public static class protector
    {
    private static readonly byte[] salt = Encoding.Unicode.GetBytes("SOMETHING");
    public static readonly int iterations = 2000;
    private static Dictionary<string, User> Users = new Dictionary<string, User>();

    public static User Register (string username, string password) {

        var autoGen = RandomNumberGenerator.Create();
        var saltBytes = new byte[16];
        autoGen.GetBytes(saltBytes);
        var saltText = Convert.ToBase64String(saltBytes);

        // generate the salted and hashed password
        var saltedHashedpassword = SaltAndHashPassword(password, saltText);
        var user = new User{
            Name = username,
            Salt = saltText,
            SaltedHashedPassword = saltedHashedpassword
        };

        Users.Add(user.Name, user);

        return user;
    }

    public static bool CheckPassword (string username, string password) {
        if (!Users.ContainsKey(username)) {
            return false;
        }

        var user = Users[username];

        // re-generate the salted and hashed password
        var saltedHashedpassword = SaltAndHashPassword(password, user.Salt);

        return (saltedHashedpassword == user.SaltedHashedPassword);
    }

    public static string SaltAndHashPassword (string password, string salt) {
        var sha = SHA256.Create();
        var saltedPassword = password + salt;

        return Convert.ToBase64String(sha.ComputeHash(Encoding.Unicode.GetBytes(saltedPassword)));
    }

    public static string Encrypt (string plainText, string password) {
      byte[] encryptedbytes;
      byte[] plainBytes = Encoding.Unicode.GetBytes(plainText);
      var aes = Aes.Create();
      var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);
      aes.Key = pbkdf2.GetBytes(32);
      aes.IV = pbkdf2.GetBytes(16);

      using (var ms = new MemoryStream())
      {
          using (var cs = new CryptoStream(
              ms,
              aes.CreateEncryptor(),
              CryptoStreamMode.Write
          ))
          {
          cs.Write(plainBytes, 0, plainBytes.Length);
        }
        encryptedbytes = ms.ToArray();
      }

      return Convert.ToBase64String(encryptedbytes);
    }

    public static string Decrypt ( string cryptoText, string password) {
      byte[] plainBytes;
      byte[] cryptoBytes = Convert.FromBase64String(cryptoText);
      var aes = Aes.Create();
      var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations);
      aes.Key = pbkdf2.GetBytes(32);
      aes.IV = pbkdf2.GetBytes(16);

      using (var ms = new MemoryStream())
      {
          using (var cs = new CryptoStream(
              ms,
              aes.CreateDecryptor(),
              CryptoStreamMode.Write
            ))
          {
          cs.Write(cryptoBytes, 0, cryptoBytes.Length);
        }
        plainBytes = ms.ToArray();
      }

      return Encoding.Unicode.GetString(plainBytes);
    }
  }
}
