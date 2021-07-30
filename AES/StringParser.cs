using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.IO;

namespace Ransomware_Beta
{
    class StringParser
    {
        private static Regex binaryStream = new Regex("(0|1)+");
        /// <summary>
        /// Converts a certain binary sequence represented as a string into a byte array of given length.
        /// </summary>
        /// <param name="sequence"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public static byte[] ToBits(String sequence, int length)
        {
            byte[] bitStream = new byte[length];
            //First make sure that the string is a sequence of 0s and 1s
            bool binaryMatched = binaryStream.IsMatch(sequence);
            if (binaryMatched && sequence.Length == length)
            {
                //Split the binary string into byte array
                for (int i = 0; i < length; i++)
                {
                    bitStream[i] = Convert.ToByte(Char.ToString(sequence[i]), 2);
                }
                return bitStream;
            }
            else
                return null;
        }
        /// <summary>
        /// Converts a hexa0decimal value represented as a string into its equilevant binary representation.
        /// </summary>
        /// <param name="hexaValue"></param>
        /// <returns></returns>
        public static byte[] ToBits(String hexaValue)
        {
            byte hexa = Convert.ToByte(hexaValue, 16);
            //Run the binary conversion algorithm on the resulted byte value
            byte quotient, rem;
            int index = 7;
            byte[] binaryStream = new byte[8];
            while (hexa > 0)
            {
                quotient = Convert.ToByte(hexa / 2);
                rem = Convert.ToByte(hexa % 2);
                hexa = quotient;
                binaryStream[index] = rem;
                index--;
            }
            return binaryStream;
        }
        /// <summary>
        /// Reads the content of the speceifed text file and returns it as a binary stream.
        /// </summary>
        /// <param name="fileName"></param>
        /// <returns></returns>
        public static byte[] ReadText(String fileName)
        {
            StreamReader reader = new StreamReader(fileName);
            String text = reader.ReadToEnd();
            reader.Close();
            //Make sure that the file is written in binary
            if (binaryStream.IsMatch(text))
            {
                byte[] bitStream = new byte[text.Length];
                //split the binary string into byte array
                for (int i = 0; i < text.Length; i++)
                {
                    bitStream[i] = Convert.ToByte(Char.ToString(text[i]), 2);
                }
                return bitStream;
            }
            return null;
        }
        /// <summary>
        /// Writes the given content into the specified text file.
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="content"></param>
        public static void WriteText(String fileName, byte[] content)
        {
            StreamWriter writer = new StreamWriter(fileName);
            for (int i = 0; i < content.Length; i++)
                writer.Write(content[i]);
            writer.Close();
        }
    }
}
