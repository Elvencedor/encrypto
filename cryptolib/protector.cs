﻿using System;
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
    public static string publicKey;

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

    public static string ToXmlStringExt (this RSA rsa, bool includePrivateParameters) {
        var p = rsa.ExportParameters(includePrivateParameters);
        XElement xml;

        if (includePrivateParameters) {
            xml =  new XElement("RSAKeyValue", 
                new XElement("Modulus", ToBase64String(p.Modulus)),
                new XElement("Exponent", ToBase64String(p.Exponent)),
                new XElement("P", ToBase64String(p.P)),
                new XElement("DQ", ToBase64String(p.DQ)),
                new XElement("DP", ToBase64String(p.DP)),
                new XElement("Q", ToBase64String(p.Q)),
                new XElement("InverseQ", ToBase64String(p.InverseQ))
            );
        } else {
            xml = new XElement("RSAKeyValue", 
                new XElement("Modulus", ToBase64String(p.Modulus)),
                new XElement("Exponent", ToBase64String(p.Exponent))
            );
        }

        return xml?.ToString();
    }

    public static void FromXmlStringExt (this RSA rsa, string parametersAsXml) {
        var xml = XDocument.Parse(parametersAsXml);
        var root = xml.Element("RSAKeyValue");
        var p = new RSAParameters {
            Modulus = FromBase64String(root.Element("Modulus").Value),
            Exponent = FromBase64String(root.Element("Exponent").Value)
        };

        if (root.Element("P") != null) {
            p.P = FromBase64String(root.Element("P").Value);
            p.Q = FromBase64String(root.Element("Q").Value);
            p.DP = FromBase64String(root.Element("DP").Value);
            p.DQ = FromBase64String(root.Element("DQ").Value);
            p.InverseQ = FromBase64String(root.Element("InverseQ").Value);
        }
        rsa.ImportParameters(p);
    }

    public static string GenerateSignature (string data) {
        byte[] dataBytes = Encoding.Unicode.GetBytes(data);
        var sha = SHA256.Create();
        var hashedData = sha.ComputeHash(dataBytes);
        var rsa = RSA.Create();
        publicKey = rsa.ToXmlStringExt(false);

        return ToBase64String(rsa.SignHash(hashedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }
  }
}
