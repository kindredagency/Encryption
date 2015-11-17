using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace Framework.AssetLibrary.Encryption.Cryptography
{
    /// <summary>
    /// Class ObjectHashGenerator.
    /// </summary>
    internal static class ObjectHashGenerator
    {
        private static readonly object Locker = new object();

        /// <summary>
        /// Computes the hash.
        /// </summary>
        /// <param name="source">The source.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <returns>System.String.</returns>
        /// <exception cref="Exception">Source object cannot be null</exception>
        public static string ComputeHash(object source, AlgorithmType hashAlgorithm)
        {
            return ComputeHash(source, hashAlgorithm, null);
        }

        /// <summary>
        /// Computes the hash.
        /// </summary>
        /// <param name="source">The source.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="saltBytes">The salt bytes.</param>
        /// <returns>System.String.</returns>
        public static string ComputeHash(object source, AlgorithmType hashAlgorithm, byte[] saltBytes)
        {
            if (source == null)
                throw new Exception(nameof(source) + " cannot be null");

            MemoryStream memoryStream = new MemoryStream();
            BinaryFormatter binaryFormatter = new BinaryFormatter();

            lock (Locker)
            {
                binaryFormatter.Serialize(memoryStream, source);
            }

            return PlainTextHashGenerator.ComputeHash(Convert.ToBase64String(memoryStream.ToArray()), hashAlgorithm, saltBytes);
        }

        /// <summary>
        /// Verifies the hash.
        /// </summary>
        /// <param name="source">The source.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="hashValue">The hash value.</param>
        /// <returns><c>true</c> if the 2 hashed values match, <c>false</c> otherwise.</returns>
        public static bool VerifyHash(object source, AlgorithmType hashAlgorithm, string hashValue)
        {
            if (source == null)
                throw new Exception(nameof(source) + " cannot be null");

            MemoryStream memoryStream = new MemoryStream();
            BinaryFormatter binaryFormatter = new BinaryFormatter();

            lock (Locker)
            {
                binaryFormatter.Serialize(memoryStream, source);
            }

            return PlainTextHashGenerator.VerifyHash(Convert.ToBase64String(memoryStream.ToArray()), hashAlgorithm, hashValue);
        }
    }
}