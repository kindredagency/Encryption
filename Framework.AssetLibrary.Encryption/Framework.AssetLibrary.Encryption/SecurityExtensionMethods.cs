using Framework.AssetLibrary.Encryption.Cryptography;

namespace Framework.AssetLibrary.Encryption
{

    /// <summary>
    /// Class SecurityExtensionMethods.
    /// </summary>
    public static class SecurityExtensionMethods
    {
        /// <summary>
        /// Computes the hash.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <param name="algorithmType">Type of the algorithm.</param>
        /// <returns>System.String.</returns>
        public static string ComputeHash(this string value, AlgorithmType algorithmType)
        {
            return PlainTextHashGenerator.ComputeHash(value, algorithmType);
        }

        /// <summary>
        /// Computes the hash.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <param name="algorithmType">Type of the algorithm.</param>
        /// <returns>System.String.</returns>
        public static string ComputeHash(this object value, AlgorithmType algorithmType)
        {
            return ObjectHashGenerator.ComputeHash(value, algorithmType);
        }

        /// <summary>
        /// Verifies the hash.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <param name="hashedValue">The hashed value.</param>
        /// <param name="algorithmType">Type of the algorithm.</param>
        /// <returns><c>true</c> if the 2 hashed values match, <c>false</c> otherwise.</returns>
        public static bool VerifyHash(this string value, string hashedValue, AlgorithmType algorithmType)
        {
            return PlainTextHashGenerator.VerifyHash(value, algorithmType, hashedValue);
        }

        /// <summary>
        /// Verifies the hash.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <param name="hashedValue">The hashed value.</param>
        /// <param name="algorithmType">Type of the algorithm.</param>
        /// <returns><c>true</c> if the 2 hashed values match, <c>false</c> otherwise.</returns>
        public static bool VerifyHash(this object value, string hashedValue, AlgorithmType algorithmType)
        {
            return ObjectHashGenerator.VerifyHash(value, algorithmType, hashedValue);
        }
    }
}