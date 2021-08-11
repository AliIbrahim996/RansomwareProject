using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AES
{
    public class Cipher
    {
        public static byte[] Encrypt(byte[] content, byte[] key, int blockLength)
        {
            AES cipher = new AES(key);
            int blockIndex = 0;
            byte[] result;
            if (content.Length % 16 == 0)
                result = new byte[content.Length];
            else
                result = new byte[content.Length + (16 - content.Length % 16)];
            while (blockIndex < content.Length)
            {
                byte[] block = new byte[blockLength];
                try
                {
                    Array.Copy(content, blockIndex, block, 0, 16);
                }
                catch (ArgumentException)
                {
                    int paddingIdx, index = 0;
                    for (paddingIdx = blockIndex - 1; paddingIdx < content.Length - blockIndex; paddingIdx++)
                    {
                        block[index] = content[paddingIdx];
                        index++;
                    }
                    block[index] = 0x1; index++;
                    while (index < block.Length)
                    {
                        block[index] = 0x00;
                        index++;
                    }
                }
                byte[] temp = cipher.Encrypt(block);
                //write the block into the result array
                Array.Copy(temp, 0, result, blockIndex, 16);
                blockIndex += 16;
            }
            return result;
            
        }
        public static byte[] Decrypt(byte[] content, byte[] key, int blockLength)
        {
            AES cipher = new AES(key);
            int blockIndex = 0;
            byte[] result = new byte[content.Length];
            while (blockIndex < content.Length)
            {
                byte[] block = new byte[blockLength];
                Array.Copy(content, blockIndex, block, 0, 16);
                byte[] temp = cipher.Decrypt(block);
                //write the block into the result 
                Array.Copy(temp, 0, result, blockIndex, 16);
                blockIndex += 16;
            }
            return result;
        }
    }
}
