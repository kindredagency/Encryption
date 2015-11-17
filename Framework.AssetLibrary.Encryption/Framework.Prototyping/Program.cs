using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Framework.AssetLibrary.Encryption;
using Framework.AssetLibrary.Encryption.Cryptography;

namespace Framework.Prototyping
{
    class Program
    {
        static void Main(string[] args)
        {
            string text = "Wee Willie Winkie runs through the town";

            Console.WriteLine(text);

            string textHash = text.ComputeHash(AlgorithmType.SHA512);

            Console.WriteLine(textHash);

            Console.WriteLine(text.VerifyHash(textHash, AlgorithmType.SHA512));

            List<string> someObject = new List<string>();

            Console.WriteLine("An object list");

            string objectHash = someObject.ComputeHash(AlgorithmType.SHA512);

            Console.WriteLine(objectHash);

            Console.WriteLine(someObject.VerifyHash(objectHash, AlgorithmType.SHA512));

            Console.ReadLine();

        }
    }
}
