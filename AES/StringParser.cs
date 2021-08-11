using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AES
{
    class StringParser
    {
        public static byte[] ToBits(byte hexaValue)
        {
            //Run the binary conversion algorithm on the resulted byte value
            byte quotient, rem;
            int index = 7;
            byte[] binaryStream = new byte[8];
            while (hexaValue > 0)
            {
                quotient = Convert.ToByte(hexaValue / 2);
                rem = Convert.ToByte(hexaValue % 2);
                hexaValue = quotient;
                binaryStream[index] = rem;
                index--;
            }
            return binaryStream;
        }
    }
}
