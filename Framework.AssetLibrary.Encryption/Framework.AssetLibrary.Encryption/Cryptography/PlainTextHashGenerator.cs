using System;
using System.Security.Cryptography;
using System.Text;

namespace Framework.AssetLibrary.Encryption.Cryptography
{
    /// <summary>
    /// Class PlainTextHashGenerator.
    /// </summary>
    internal class PlainTextHashGenerator
    { 
        /// <summary>
        /// Computes the hash.
        /// </summary>
        /// <param name="plainText">The plain text.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <returns>System.String.</returns>
        public static string ComputeHash(string plainText, AlgorithmType hashAlgorithm)
        {
            return ComputeHash(plainText, hashAlgorithm, null);
        }

        /// <summary>
        /// Computes the hash.
        /// </summary>
        /// <param name="plainText">The plain text.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="saltBytes">The salt bytes.</param>
        /// <returns>System.String.</returns>
        public static string ComputeHash(string plainText, AlgorithmType hashAlgorithm, byte[] saltBytes)
        {
            if (plainText == null)
                throw new Exception(nameof(plainText) + " cannot be null");

            // If salt is not specified, generate it on the fly.
            if (saltBytes == null)
            {
                // Define min and max salt sizes.
                var minSaltSize = 4;
                var maxSaltSize = 8;

                // Generate a random number for the size of the salt.
                var random = new Random();
                var saltSize = random.Next(minSaltSize, maxSaltSize);

                // Allocate a byte array, which will hold the salt.
                saltBytes = new byte[saltSize];

                // Initialize a random number generator.
                var rng = new RNGCryptoServiceProvider();

                // Fill the salt with cryptographically strong byte values.
                rng.GetNonZeroBytes(saltBytes);
            }

            // Convert plain text into a byte array.
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            // Allocate array, which will hold plain text and salt.
            var plainTextWithSaltBytes =
                new byte[plainTextBytes.Length + saltBytes.Length];

            // Copy plain text bytes into resulting array.
            for (var i = 0; i < plainTextBytes.Length; i++)
                plainTextWithSaltBytes[i] = plainTextBytes[i];

            // Append salt bytes to the resulting array.
            for (var i = 0; i < saltBytes.Length; i++)
                plainTextWithSaltBytes[plainTextBytes.Length + i] = saltBytes[i];

            // Because we support multiple hashing algorithms, we must define
            // hash object as a common (abstract) base class. We will specify the
            // actual hashing algorithm class later during object creation.
            HashAlgorithm hashServiceProvider;

            // Initialize appropriate hashing algorithm class.
            switch (hashAlgorithm.ToString().ToUpper())
            {
                case "SHA1":
                    hashServiceProvider = new SHA1Managed();
                    break;

                case "SHA256":
                    hashServiceProvider = new SHA256Managed();
                    break;

                case "SHA384":
                    hashServiceProvider = new SHA384Managed();
                    break;

                case "SHA512":
                    hashServiceProvider = new SHA512Managed();
                    break;

                case "MD5":
                    hashServiceProvider = new MD5CryptoServiceProvider();
                    break;

                default:
                    hashServiceProvider = new MD5CryptoServiceProvider();
                    break;
            }

            // Compute hash value of our plain text with appended salt.
            var hashBytes = hashServiceProvider.ComputeHash(plainTextWithSaltBytes);

            // Create array which will hold hash and original salt bytes.
            var hashWithSaltBytes = new byte[hashBytes.Length + saltBytes.Length];

            // Copy hash bytes into resulting array.
            for (var i = 0; i < hashBytes.Length; i++)
                hashWithSaltBytes[i] = hashBytes[i];

            // Append salt bytes to the result.
            for (var i = 0; i < saltBytes.Length; i++)
                hashWithSaltBytes[hashBytes.Length + i] = saltBytes[i];

            // Convert result into a base64-encoded string.
            var hashValue = Convert.ToBase64String(hashWithSaltBytes);

            // Return the result.
            return hashValue;
        }

        /// <summary>
        /// Verifies the hash.
        /// </summary>
        /// <param name="plainText">The plain text.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="hashValue">The hash value.</param>
        /// <returns><c>true</c>  if the 2 hashed values match, <c>false</c> otherwise.</returns>
        public static bool VerifyHash(string plainText, AlgorithmType hashAlgorithm, string hashValue)
        {
            // Convert base64-encoded hash value into a byte array.
            var hashWithSaltBytes = Convert.FromBase64String(hashValue);

            // We must know size of hash (without salt).
            int hashSizeInBits;

            // Size of hash is based on the specified algorithm.
            switch (hashAlgorithm.ToString().ToUpper())
            {
                case "SHA1":
                    hashSizeInBits = 160;
                    break;

                case "SHA256":
                    hashSizeInBits = 256;
                    break;

                case "SHA384":
                    hashSizeInBits = 384;
                    break;

                case "SHA512":
                    hashSizeInBits = 512;
                    break;

                default: // Must be MD5
                    hashSizeInBits = 128;
                    break;
            }

            // Convert size of hash from bits to bytes.
            var hashSizeInBytes = hashSizeInBits / 8;

            // Make sure that the specified hash value is long enough.
            if (hashWithSaltBytes.Length < hashSizeInBytes)
                return false;

            // Allocate array to hold original salt bytes retrieved from hash.
            var saltBytes = new byte[hashWithSaltBytes.Length - hashSizeInBytes];

            // Copy salt from the end of the hash to the new array.
            for (var i = 0; i < saltBytes.Length; i++)
                saltBytes[i] = hashWithSaltBytes[hashSizeInBytes + i];

            // Compute a new hash string.
            var expectedHashString = ComputeHash(plainText, hashAlgorithm, saltBytes);

            // If the computed hash matches the specified hash,
            // the plain text value must be correct.
            return (hashValue == expectedHashString);
        }
    }
}