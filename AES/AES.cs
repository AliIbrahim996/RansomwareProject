using System;
using System.Text;

namespace AES
{
   public class AES
    {
        //Data members
        /// <summary>
        /// Represents the initial 128-bits key that will be used to create the round-keys
        /// usually written in hexadecimal notation.
        /// </summary>
        private String[,] initialKey;
        /// <summary>
        /// A 16x16 Substitution Box(S-Box) used in key schedule step and in encryption.
        /// </summary>
        private byte[,] SBox ={   {0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76},
                                 {0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0},
                                 {0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15},
                                 {0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75},
                                 {0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84},
                                 {0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF},
                                 {0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8},
                                 {0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2},
                                 {0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73},
                                 {0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB},
                                 {0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79},
                                 {0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08},
                                 {0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A},
                                 {0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E},
                                 {0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF},
                                 {0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16}};
        /// <summary>
        /// Represents a two dimensional matrix of 10 rows and 4 columns that holds the values of
        /// the round keys as System.UInt32 objects.
        /// </summary>
        private UInt32[,] roundKeys;
        /// <summary>
        /// Represents the constants used in special conditions during key-exapnsion step in AES.
        /// </summary>
        private byte[,] rCon ={ {0x01,0x00,0x00,0x00},{0x02,0x00,0x00,0x00},{0x04,0x00,0x00,0x00},
                               {0x08,0x00,0x00,0x00},{0x10,0x00,0x00,0x00},{0x20,0x00,0x00,0x00},
                               {0x40,0x00,0x00,0x00},{0x80,0x00,0x00,0x00},{0x1B,0x00,0x00,0x00},
                               {0x36,0x00,0x00,0x00}};
        /// <summary>
        /// Represents a 4x4 array of hexadecimal values that will be used in MixColumns step in encryption.
        /// </summary>
        private byte[,] mixingMatrix ={ {0x02,0x03,0x01,0x01},{0x01,0x02,0x03,0x01},
                                        {0x01,0x01,0x02,0x03},{0x03,0x01,0x01,0x02}};
        //Constructor
        public AES(String key)     //Key constructed successfully
        {
            this.initialKey = new String[4, 4];
            separateKeyValues(key);
            this.roundKeys = new UInt32[10, 4];
        }
        /// <summary>
        /// Separates the contents of the specified System.String object into an array of hexadecimal
        /// values with every cell containing two hexadecimal numbers.
        /// </summary>
        /// <param name="key">The String to separate</param>
        private void separateKeyValues(String key)
        {
            int colIndex = 0, rowIndex = 0;
            for (int i = 0; i < key.Length; i += 2)
            {
                this.initialKey[rowIndex, colIndex % 4] = Char.ToString(key[i]) + Char.ToString(key[i + 1]);
                colIndex++;
                if (colIndex % 4 == 0)
                    rowIndex++;
            }
            Console.WriteLine("Initial Key....\nresult...");
            for (int i = 0; i < this.initialKey.GetLength(0); i++)
            {
                for (int j = 0; j < this.initialKey.GetLength(1); j++)
                    Console.Write(this.initialKey[i, j] + " ");
                Console.WriteLine();
            }
        }
        /// <summary>
        /// Performs the key scheduling process in AES-128 to produce 11 keys each a 16-byte length.
        /// </summary>
        internal void ExpandKey()   //Passed Successfully
        {
            UInt32[] words = new UInt32[44];
            //index to iterate on the initial key vector,iter to iterate over the words vector
            int index = 0, iter = 0, col = 0;
            //Build the first 4 words based on the initial key 
            while (index < 16)
            {
                //To  use the built-in class BitConverter to ease the conversion between byte-array and UInt32
                byte[] key = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    key[i] = Convert.ToByte(this.initialKey[index%4, col], 16); //Converts a string object into an array of bytes.
                    index++;
                }
                col++;
                words[iter] = BitConverter.ToUInt32(key, 0);
                Console.WriteLine("Word # {0} is  {1}", iter,BitConverter.ToString(BitConverter.GetBytes( words[iter]),0));
                iter++;
            }
            //reset index to use it again as colIndex in round-keys scheduling
            index = 0;
            int rowIndex = 0;
            //Build the round keys
            for (iter = 4; iter < 44; iter++)
            {
                //byte[] helper = new byte[4];
                if (iter % 4 != 0)
                {
                    words[iter] = words[iter - 1] ^ words[iter - 4];
                }

                else
                {
                    UInt32 roundConstant = GetConstant(iter);
                    UInt32 temp = SubWord(RotWord(words[iter - 1])) ^ roundConstant;
                    words[iter] = words[iter - 4] ^ temp;
                }
                //var helper = BitConverter.GetBytes(words[iter]);
                //Console.WriteLine("Word # {0} is  {1}", iter, BitConverter.ToString(helper, 0));
                this.roundKeys[rowIndex, index % 4] = words[iter];
                Console.WriteLine("Round key # {0} is\n{1}", rowIndex, BitConverter.ToString(BitConverter.GetBytes(this.roundKeys[rowIndex, index % 4] = words[iter])));
                index++;
                if (index % 4 == 0)
                    rowIndex++;
            }
        }
        /// <summary>
        /// Returns the corresponding constant word as a System.UInt32 object based on the specified round key.
        /// </summary>
        /// <param name="roundIndex">The round at which the exapnsion key process is at.</param>
        /// <returns>The constant word</returns>
        private UInt32 GetConstant(int roundIndex)   //Passed Testing successfully
        {
            byte[] temp = new byte[4];
            //Extract the row index in the constant matrix that corresponds to the scheduled round
            int index = (roundIndex / 4) - 1;
            for (int i = 0; i < 4; i++)
                temp[i] = this.rCon[index, i];
            UInt32 constant = BitConverter.ToUInt32(temp, 0);
            return constant;
        }
        /// <summary>
        /// Applies a one-byte cyclic shift-to-left to the specified System.UInt32 object.
        /// </summary>
        /// <param name="word">The word to rotate.</param>
        /// <returns>The word after rotation.</returns>
        private UInt32 RotWord(UInt32 word)    //Passed unit testing successfully
        {
            byte[] temp = BitConverter.GetBytes(word);
            var rep = temp[0];
            for (int i = 0; i < 3; i++)
                temp[i] = temp[i + 1];
            temp[3] = rep;
            UInt32 rotated = BitConverter.ToUInt32(temp, 0);
            return rotated;
        }
        /// <summary>
        /// Substitute each byte of the 4-byte-length specified System.UInt32 object according to the S-Box used in AES.
        /// </summary>
        /// <param name="word">The 4-byte-length word to substitute.</param>
        /// <returns>A 4-byte-length System.UInt32 object after substitution.</returns>
        private UInt32 SubWord(UInt32 word)  //Passed unit test successfully
        {
            //Re-obtain the equilevant 4-bytes-vector to the specified word(32-bits)
            byte[] temp = BitConverter.GetBytes(word);
            for (int i = 0; i < 4; i++)
            {
                //Convert the value of the ith element into an equilevant hexadecimal-string representation
                String val = (BitConverter.ToString(temp, i, 1));
                //Find the appropriate value in the S-Box to replace with,(val.Substring(0,1), 16) is the row index
                //(val.Substring(1),16) the column index
                var sub = this.SBox[Convert.ToByte(val.Substring(0, 1), 16), Convert.ToByte(val.Substring(1), 16)];
                temp[i] = sub;
            }
            UInt32 subWord = BitConverter.ToUInt32(temp, 0);
            return subWord;
        }
        /// <summary>
        /// Represents the main step in AES-128 performs four main steps in 10 rounds of encrytping the same block 
        /// of data.
        /// </summary>
        /// <param name="text">The text to encrypt.</param>
        /// <returns></returns>
        internal String encrypt(String text)
        {
            //First convert the 128-bits string into state matrix
            int colIndex = 0, rowIndex = 0;
            String[,] state = new String[4, 4];
            for (int i = 0; i < text.Length; i += 2)
            {
               state[rowIndex, colIndex % 4] = Char.ToString(text[i]) + Char.ToString(text[i + 1]);
                colIndex++;
                if (colIndex % 4 == 0)
                    rowIndex++;
            }
            //Make sure the state is written correctly
            Console.WriteLine("State Matrix construction....\nresult...");
            for (int i = 0; i < state.GetLength(0); i++)
            {
                for (int j = 0; j < state.GetLength(1); j++)
                    Console.Write(state[i, j] + " ");
                Console.WriteLine();
            }
            //Add initial key aka, the whitening step
            // HexaSystem.StringToHexa(text);
            byte[,] stateValues = new byte[state.GetLength(0), state.GetLength(1)];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    byte[] res = { Convert.ToByte(Convert.ToByte(state[i, j], 16) ^
                                     Convert.ToByte(this.initialKey[i, j], 16)) };
                    state[i, j] = BitConverter.ToString(res, 0);
                }
            }
            Console.WriteLine("Finished whitening....\nresult...");
            for(int i=0;i<state.GetLength(0);i++)
            {
                for (int j = 0; j < state.GetLength(1); j++)
                    Console.Write(state[i, j] + " ");
                Console.WriteLine();
            }
            //Start the rounds of the algorithm
            int round = 0;
            while (round < 10)
            {
                state = SubByte(state);
                state = ShiftRow(state);
                Console.WriteLine("After Shifted Rows......");
                for (int i = 0; i < state.GetLength(0); i++)
                {
                    for (int j = 0; j < state.GetLength(1); j++)
                        Console.Write(state[i, j] + " ");
                    Console.WriteLine();
                }
                if (round != 9)
                {
                    state = MixColumns(state);
                    Console.WriteLine("After Mixing Columns....\nresult...");
                    for (int i = 0; i < state.GetLength(0); i++)
                    {
                        for (int j = 0; j < state.GetLength(1); j++)
                            Console.Write(state[i, j] + " ");
                        Console.WriteLine();
                    }
                }
                state = AddRoundKey(state, round);
                Console.WriteLine("After Adding RoundKey {0}....\nresult...", round);
                for (int i = 0; i < state.GetLength(0); i++)
                {
                    for (int j = 0; j < state.GetLength(1); j++)
                        Console.Write(state[i, j] + " ");
                    Console.WriteLine();
                }
                round++;
            }
            StringBuilder encrypted = new StringBuilder();
            for (int i = 0; i < state.GetLength(0); i++)
                for (int j = 0; j < state.GetLength(1); j++)
                    encrypted.Append(state[i, j]);
            return encrypted.ToString();
        }
        /// <summary>
        /// Replaces every cell of the specified hexadecimal System.String two dimensional array
        /// according ot the pre-defined S-Box in AES.
        /// </summary>
        /// <param name="state">The two dimensional array of hexadecimal strings.</param>
        /// <returns>The two dimensional array after substitution.</returns>
        private String[,] SubByte(String[,] state)    //Passed unit test successfully.
        {
            for (int i = 0; i < state.GetLength(0); i++)
            {
                for (int j = 0; j < state.GetLength(1); j++)
                {
                    String val = state[i, j];
                    byte[] sub = { this.SBox[Convert.ToByte(val.Substring(0, 1), 16), Convert.ToByte(val.Substring(1), 16)] };
                    state[i, j] = BitConverter.ToString(sub, 0);
                }
            }
            return state;
        }
        /// <summary>
        /// Applies a row-dependent byte-level shift-to-left to each row of the specified System.String two dimensional array.
        /// </summary>
        /// <param name="state">The two dimensional array to shift.</param>
        /// <returns></returns>
        internal String[,] ShiftRow(String[,] state) //Passed unit testing
        {
            //We need to define another matrix since the shift is not fixed.
            String[,] shifted = new String[4, 4];
            for (int k = 0; k < 4; k++)
                shifted[0, k] = state[0, k];
            for (int round = 1; round < 4; round++)
            {
                Console.WriteLine("Why am I not leaving this round...{0}", round);
                //Find which element would be placed at cell [round,0] and store its value.
                var rep = state[round, round];  //correct
                Console.WriteLine("Replace: " + rep);
                for (int i = 0; i < 4; i++)
                {
                    //Add % to allow cyclic shift-to-left which depends on the index of the current row indicated by round.
                    shifted[round, i] = state[round, (i + round) % 4];
                    Console.WriteLine(shifted[round, i]);
                }
                shifted[round, 0] = rep;
                Console.WriteLine("I'm here...... at round{0}", round);
                if (round == 3)
                    break;
            }
            Console.WriteLine("Left ShiftRow you'd better check somewhere else!!!");
            return shifted;
        }
        /// <summary>
        /// Multiplies the specifed two dimensional array of System.String objects with the pre-defined matrix in GF(256)
        /// to deliver diffusion to the encryption process.
        /// </summary>
        /// <param name="state">The current state of the input file/text.</param>
        /// <returns></returns>
        internal String[,] MixColumns(String[,] state)  //Passed unit test successfully.
        {
            Console.WriteLine("Starting MixColumns.....");
            String[,] mixed = new String[state.GetLength(0), state.GetLength(1)];
            byte result = 0;
            //An ordinary variable would have hold but we're using a trick to invoke BitConverter.ToString(byte[]).
            byte[] sum = new byte[1];
            //Add 3 for-loops in order to find the matrices multiplications.
            for (int i = 0; i < this.mixingMatrix.GetLength(0); i++)
            {
                //First loop to iterate over the rows of the resulted matrix,at each iteration reset sum to 0.
                for (int j = 0; j < state.GetLength(1); j++)
                {
                    //Second loop to iterate over the columns of the state marix
                    sum[0] = 0x00;
                    for (int k = 0; k < this.mixingMatrix.GetLength(1); k++)
                    {
                        result = 0x00;
                        //Here where the real work is!
                        if (this.mixingMatrix[i, k] == 0x03)
                        {
                            //If the cuurent multiplier is 0x03 we need to distribute the multiplication over addition
                            //i.e,0x03*x= x + 0x02*x
                            //Note applying XOR after or before MulInGF would not change the result.
                            result = Convert.ToByte(MulInGF(StringParser.ToBits(state[k, j])) ^ Convert.ToByte(state[k, j], 16));
                        }
                        else
                            if (this.mixingMatrix[i, k] == 0x02)
                            {
                                //If the current multiplier is 0x02 only a multiplication in the field GF(256) is done
                                //which implictly involves shifting by one bit to left and xoring with 0x1B if neccessary.
                                result = MulInGF(StringParser.ToBits(state[k, j]));
                            }
                            else
                            {
                                //The multiplier is hence 0x01 and the result is the same hexadecimal value.
                                result = Convert.ToByte(state[k, j], 16);
                            }
                        sum[0] = Convert.ToByte(result ^ sum[0]);
                    }
                    mixed[i, j] = BitConverter.ToString(sum, 0);
                    Console.WriteLine(mixed[i, j]);
                }
            }
            Console.WriteLine("Left Mix Clolumns better check somewhere else");
            return mixed;
        }
        /// <summary>
        /// Applies a non-cyclic shift-to-left to the specified System.Byte array and replaces the right-most element
        /// with zero in order to perform multiplying in GF(2^8) by the constant 0x1B if neccessary.
        /// </summary>
        /// <param name="bits">An array of 0s and 1s.</param>
        /// <returns>The corresponding hexadecimal value after shifting and multiplying.</returns>
        internal byte MulInGF(byte[] bits)    //Passed unit testing.
        {
            StringBuilder shifted = new StringBuilder();
            //Define the field constant.
            byte irred = 0x1B;
            //Shift the bits to left by appending all but first element to the StringBuilder object.
            for (int i = 0; i < bits.Length - 1; i++)
                shifted.Append(bits[i + 1]);
            //Add the right-most bit which is 0 because the shift is a non-cyclic shift.
            shifted.Append(0);
            byte xored = 0;
            byte actualValue = 0;
            if (bits[0] == 1)
            {
                xored = Convert.ToByte(Convert.ToByte(shifted.ToString(), 2) ^ irred);
                shifted = new StringBuilder(xored.ToString("X"));
                actualValue = Convert.ToByte(shifted.ToString(), 16);
            }
            else
                actualValue = Convert.ToByte(shifted.ToString(), 2);
            return actualValue;
        }
        /// <summary>
        /// Performs a bitwise XOR operation to the specified System.String[,] array with the corresponding round key.
        /// </summary>
        /// <param name="state">The current state of the input data.</param>
        /// <param name="round">The round at which the encryption process is currently at.</param>
        /// <returns></returns>
        internal String[,] AddRoundKey(String[,] state, int round)
        {
            byte[,] stateValues = new byte[state.GetLength(0), state.GetLength(1)];
            //separate the UInt32 round key values into 16 bytes to eable bitwise XOR operation.
            //byte[] roundKey = new byte[state.Length];  //Holds the values of the round keys as byte values.
            byte[,] roundKey = new byte[state.GetLength(0), state.GetLength(1)];
            int index = 0, colIndex = 0;
            while (index < 4)
            {
                byte[] temp = BitConverter.GetBytes(this.roundKeys[round, index]);
                for (int i = 0; i < temp.Length; i++)
                {
                    roundKey[i, colIndex] = temp[i];//filling column by column
                    Console.Write(temp[i] + " ");
                    //roundKey[i] = temp[i];
                }
                Console.WriteLine("######################");
                index++;
                //added
                colIndex++;
            }
            Console.WriteLine("Round key is....\nresult...");
            for (int i = 0; i < roundKey.GetLength(0); i++)
            {
                for (int j = 0; j < roundKey.GetLength(1); j++)
                    Console.Write(Convert.ToString(roundKey[i, j], 16)+ " ");
                Console.WriteLine();
            }
            Console.WriteLine();
            //Perform the Bitwise XOR operation on the element of the state matrix.
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    byte[] res = { Convert.ToByte(Convert.ToByte(state[i, j], 16) ^ roundKey[i,j]) };
                    state[i, j] = BitConverter.ToString(res, 0);
                }
            }
            return state;
        }
        internal void PrintKey()
        {
            for (int i = 0; i < this.roundKeys.GetLength(0); i++)
            {
                for (int j = 0; j < this.roundKeys.GetLength(1); j++)
                {
                    byte[] temp = BitConverter.GetBytes(this.roundKeys[i, j]);
                    string hexa = BitConverter.ToString(temp, 0);
                    Console.Write(hexa + "   ");
                }
                Console.WriteLine();
            }
        }
    }
}
