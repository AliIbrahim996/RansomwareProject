using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AES
{
    class AES
    {
        //Data members
        /// <summary>
        /// Represents the initial 128-bits key that will be used to create the round-keys
        /// usually written in hexadecimal notation.
        /// </summary>
        private byte[,] initialKey;
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
        ///<summary>
        ///Represents the inversed Substitution Box which will be used in decryption.
        ///</summmary>
        byte[,] invSBox ={{0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
                         {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
                         {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
                         {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
                         {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
                         {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
                         {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
                         {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
                         {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
                         {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
                         {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
                         {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
                         {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
                         {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
                         {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
                         {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D} };
        ///<summary>
        ///Represents the inversed Mixing Matrix which will be used in decryption.
        ///</summary>
        byte[,] invMixingMat ={{0x0E, 0x0B, 0x0D, 0x09},{0x09, 0x0E, 0x0B, 0x0D},
                               {0x0D, 0x09, 0x0E, 0x0B},{0x0B, 0x0D, 0x09, 0x0E}};
        /// <summary>
        /// 
        /// </summary>
        byte[,] mulBy09 = { {0x00,0x09,0x12,0x1b,0x24,0x2d,0x36,0x3f,0x48,0x41,0x5a,0x53,0x6c,0x65,0x7e,0x77},
                            {0x90,0x99,0x82,0x8b,0xb4,0xbd,0xa6,0xaf,0xd8,0xd1,0xca,0xc3,0xfc,0xf5,0xee,0xe7},
                            {0x3b,0x32,0x29,0x20,0x1f,0x16,0x0d,0x04,0x73,0x7a,0x61,0x68,0x57,0x5e,0x45,0x4c},
                            {0xab,0xa2,0xb9,0xb0,0x8f,0x86,0x9d,0x94,0xe3,0xea,0xf1,0xf8,0xc7,0xce,0xd5,0xdc},
                            {0x76,0x7f,0x64,0x6d,0x52,0x5b,0x40,0x49,0x3e,0x37,0x2c,0x25,0x1a,0x13,0x08,0x01},
                            {0xe6,0xef,0xf4,0xfd,0xc2,0xcb,0xd0,0xd9,0xae,0xa7,0xbc,0xb5,0x8a,0x83,0x98,0x91},
                            {0x4d,0x44,0x5f,0x56,0x69,0x60,0x7b,0x72,0x05,0x0c,0x17,0x1e,0x21,0x28,0x33,0x3a},
                            {0xdd,0xd4,0xcf,0xc6,0xf9,0xf0,0xeb,0xe2,0x95,0x9c,0x87,0x8e,0xb1,0xb8,0xa3,0xaa},
                            {0xec,0xe5,0xfe,0xf7,0xc8,0xc1,0xda,0xd3,0xa4,0xad,0xb6,0xbf,0x80,0x89,0x92,0x9b},
                            {0x7c,0x75,0x6e,0x67,0x58,0x51,0x4a,0x43,0x34,0x3d,0x26,0x2f,0x10,0x19,0x02,0x0b},
                            {0xd7,0xde,0xc5,0xcc,0xf3,0xfa,0xe1,0xe8,0x9f,0x96,0x8d,0x84,0xbb,0xb2,0xa9,0xa0},
                            {0x47,0x4e,0x55,0x5c,0x63,0x6a,0x71,0x78,0x0f,0x06,0x1d,0x14,0x2b,0x22,0x39,0x30},
                            {0x9a,0x93,0x88,0x81,0xbe,0xb7,0xac,0xa5,0xd2,0xdb,0xc0,0xc9,0xf6,0xff,0xe4,0xed},
                            {0x0a,0x03,0x18,0x11,0x2e,0x27,0x3c,0x35,0x42,0x4b,0x50,0x59,0x66,0x6f,0x74,0x7d},
                            {0xa1,0xa8,0xb3,0xba,0x85,0x8c,0x97,0x9e,0xe9,0xe0,0xfb,0xf2,0xcd,0xc4,0xdf,0xd6},
                            {0x31,0x38,0x23,0x2a,0x15,0x1c,0x07,0x0e,0x79,0x70,0x6b,0x62,0x5d,0x54,0x4f,0x46}};
        /// <summary>
        /// 
        /// </summary>
        byte[,] mulBy0B = { {0x00,0x0b,0x16,0x1d,0x2c,0x27,0x3a,0x31,0x58,0x53,0x4e,0x45,0x74,0x7f,0x62,0x69},
                            {0xb0,0xbb,0xa6,0xad,0x9c,0x97,0x8a,0x81,0xe8,0xe3,0xfe,0xf5,0xc4,0xcf,0xd2,0xd9},
                            {0x7b,0x70,0x6d,0x66,0x57,0x5c,0x41,0x4a,0x23,0x28,0x35,0x3e,0x0f,0x04,0x19,0x12},
                            {0xcb,0xc0,0xdd,0xd6,0xe7,0xec,0xf1,0xfa,0x93,0x98,0x85,0x8e,0xbf,0xb4,0xa9,0xa2},
                            {0xf6,0xfd,0xe0,0xeb,0xda,0xd1,0xcc,0xc7,0xae,0xa5,0xb8,0xb3,0x82,0x89,0x94,0x9f},
                            {0x46,0x4d,0x50,0x5b,0x6a,0x61,0x7c,0x77,0x1e,0x15,0x08,0x03,0x32,0x39,0x24,0x2f},
                            {0x8d,0x86,0x9b,0x90,0xa1,0xaa,0xb7,0xbc,0xd5,0xde,0xc3,0xc8,0xf9,0xf2,0xef,0xe4},
                            {0x3d,0x36,0x2b,0x20,0x11,0x1a,0x07,0x0c,0x65,0x6e,0x73,0x78,0x49,0x42,0x5f,0x54},
                            {0xf7,0xfc,0xe1,0xea,0xdb,0xd0,0xcd,0xc6,0xaf,0xa4,0xb9,0xb2,0x83,0x88,0x95,0x9e},
                            {0x47,0x4c,0x51,0x5a,0x6b,0x60,0x7d,0x76,0x1f,0x14,0x09,0x02,0x33,0x38,0x25,0x2e},
                            {0x8c,0x87,0x9a,0x91,0xa0,0xab,0xb6,0xbd,0xd4,0xdf,0xc2,0xc9,0xf8,0xf3,0xee,0xe5},
                            {0x3c,0x37,0x2a,0x21,0x10,0x1b,0x06,0x0d,0x64,0x6f,0x72,0x79,0x48,0x43,0x5e,0x55},
                            {0x01,0x0a,0x17,0x1c,0x2d,0x26,0x3b,0x30,0x59,0x52,0x4f,0x44,0x75,0x7e,0x63,0x68},
                            {0xb1,0xba,0xa7,0xac,0x9d,0x96,0x8b,0x80,0xe9,0xe2,0xff,0xf4,0xc5,0xce,0xd3,0xd8},
                            {0x7a,0x71,0x6c,0x67,0x56,0x5d,0x40,0x4b,0x22,0x29,0x34,0x3f,0x0e,0x05,0x18,0x13},
                            {0xca,0xc1,0xdc,0xd7,0xe6,0xed,0xf0,0xfb,0x92,0x99,0x84,0x8f,0xbe,0xb5,0xa8,0xa3} };
        /// <summary>
        /// 
        /// </summary>
        byte[,] mulBy0D = { {0x00,0x0d,0x1a,0x17,0x34,0x39,0x2e,0x23,0x68,0x65,0x72,0x7f,0x5c,0x51,0x46,0x4b},
                            {0xd0,0xdd,0xca,0xc7,0xe4,0xe9,0xfe,0xf3,0xb8,0xb5,0xa2,0xaf,0x8c,0x81,0x96,0x9b},
                            {0xbb,0xb6,0xa1,0xac,0x8f,0x82,0x95,0x98,0xd3,0xde,0xc9,0xc4,0xe7,0xea,0xfd,0xf0},
                            {0x6b,0x66,0x71,0x7c,0x5f,0x52,0x45,0x48,0x03,0x0e,0x19,0x14,0x37,0x3a,0x2d,0x20},
                            {0x6d,0x60,0x77,0x7a,0x59,0x54,0x43,0x4e,0x05,0x08,0x1f,0x12,0x31,0x3c,0x2b,0x26},
                            {0xbd,0xb0,0xa7,0xaa,0x89,0x84,0x93,0x9e,0xd5,0xd8,0xcf,0xc2,0xe1,0xec,0xfb,0xf6},
                            {0xd6,0xdb,0xcc,0xc1,0xe2,0xef,0xf8,0xf5,0xbe,0xb3,0xa4,0xa9,0x8a,0x87,0x90,0x9d},
                            {0x06,0x0b,0x1c,0x11,0x32,0x3f,0x28,0x25,0x6e,0x63,0x74,0x79,0x5a,0x57,0x40,0x4d},
                            {0xda,0xd7,0xc0,0xcd,0xee,0xe3,0xf4,0xf9,0xb2,0xbf,0xa8,0xa5,0x86,0x8b,0x9c,0x91},
                            {0x0a,0x07,0x10,0x1d,0x3e,0x33,0x24,0x29,0x62,0x6f,0x78,0x75,0x56,0x5b,0x4c,0x41},
                            {0x61,0x6c,0x7b,0x76,0x55,0x58,0x4f,0x42,0x09,0x04,0x13,0x1e,0x3d,0x30,0x27,0x2a},
                            {0xb1,0xbc,0xab,0xa6,0x85,0x88,0x9f,0x92,0xd9,0xd4,0xc3,0xce,0xed,0xe0,0xf7,0xfa},
                            {0xb7,0xba,0xad,0xa0,0x83,0x8e,0x99,0x94,0xdf,0xd2,0xc5,0xc8,0xeb,0xe6,0xf1,0xfc},
                            {0x67,0x6a,0x7d,0x70,0x53,0x5e,0x49,0x44,0x0f,0x02,0x15,0x18,0x3b,0x36,0x21,0x2c},
                            {0x0c,0x01,0x16,0x1b,0x38,0x35,0x22,0x2f,0x64,0x69,0x7e,0x73,0x50,0x5d,0x4a,0x47},
                            {0xdc,0xd1,0xc6,0xcb,0xe8,0xe5,0xf2,0xff,0xb4,0xb9,0xae,0xa3,0x80,0x8d,0x9a,0x97} };
        /// <summary>
        /// 
        /// </summary>
        byte[,] mulBy0E = { {0x00,0x0e,0x1c,0x12,0x38,0x36,0x24,0x2a,0x70,0x7e,0x6c,0x62,0x48,0x46,0x54,0x5a},
                            {0xe0,0xee,0xfc,0xf2,0xd8,0xd6,0xc4,0xca,0x90,0x9e,0x8c,0x82,0xa8,0xa6,0xb4,0xba},
                            {0xdb,0xd5,0xc7,0xc9,0xe3,0xed,0xff,0xf1,0xab,0xa5,0xb7,0xb9,0x93,0x9d,0x8f,0x81},
                            {0x3b,0x35,0x27,0x29,0x03,0x0d,0x1f,0x11,0x4b,0x45,0x57,0x59,0x73,0x7d,0x6f,0x61},
                            {0xad,0xa3,0xb1,0xbf,0x95,0x9b,0x89,0x87,0xdd,0xd3,0xc1,0xcf,0xe5,0xeb,0xf9,0xf7},
                            {0x4d,0x43,0x51,0x5f,0x75,0x7b,0x69,0x67,0x3d,0x33,0x21,0x2f,0x05,0x0b,0x19,0x17},
                            {0x76,0x78,0x6a,0x64,0x4e,0x40,0x52,0x5c,0x06,0x08,0x1a,0x14,0x3e,0x30,0x22,0x2c},
                            {0x96,0x98,0x8a,0x84,0xae,0xa0,0xb2,0xbc,0xe6,0xe8,0xfa,0xf4,0xde,0xd0,0xc2,0xcc},
                            {0x41,0x4f,0x5d,0x53,0x79,0x77,0x65,0x6b,0x31,0x3f,0x2d,0x23,0x09,0x07,0x15,0x1b},
                            {0xa1,0xaf,0xbd,0xb3,0x99,0x97,0x85,0x8b,0xd1,0xdf,0xcd,0xc3,0xe9,0xe7,0xf5,0xfb},
                            {0x9a,0x94,0x86,0x88,0xa2,0xac,0xbe,0xb0,0xea,0xe4,0xf6,0xf8,0xd2,0xdc,0xce,0xc0},
                            {0x7a,0x74,0x66,0x68,0x42,0x4c,0x5e,0x50,0x0a,0x04,0x16,0x18,0x32,0x3c,0x2e,0x20},
                            {0xec,0xe2,0xf0,0xfe,0xd4,0xda,0xc8,0xc6,0x9c,0x92,0x80,0x8e,0xa4,0xaa,0xb8,0xb6},
                            {0x0c,0x02,0x10,0x1e,0x34,0x3a,0x28,0x26,0x7c,0x72,0x60,0x6e,0x44,0x4a,0x58,0x56},
                            {0x37,0x39,0x2b,0x25,0x0f,0x01,0x13,0x1d,0x47,0x49,0x5b,0x55,0x7f,0x71,0x63,0x6d},
                            {0xd7,0xd9,0xcb,0xc5,0xef,0xe1,0xf3,0xfd,0xa7,0xa9,0xbb,0xb5,0x9f,0x91,0x83,0x8d} };
        //Constructor
        /// <summary>
        /// Creates a new instance of AES-128 cipher with encryption key entered as a string sequence (each one byte)
        /// </summary>
        /// <param name="key">The encryption key.</param>
        public AES(String key)     //Key constructed successfully
        {
            this.initialKey = new byte[4, 4];
            separateKeyValues(key);
            this.roundKeys = new UInt32[10, 4];
            ExpandKey();
        }
        /// <summary>
        /// Creates a new instance of A£S-128 cipher with encryption key entered as byte array, most suitable for 
        /// keys which will be read from files.
        /// </summary>
        /// <param name="key">The encryption key</param>
        public AES(byte[] key)
        {
            this.initialKey = new byte[4, 4];
            int colIndex = 0, rowIndex = 0;
            for (int i = 0; i < key.Length; i++)
            {
                this.initialKey[rowIndex % 4, colIndex % 4] = key[i];
                rowIndex++;
                if (rowIndex % 4 == 0)
                    colIndex++;
            }
            this.roundKeys = new UInt32[10, 4];
            ExpandKey();
        }
        /// <summary>
        /// Separates the contents of the specified System.String object into an array of hexadecimal
        /// values with every cell containing two hexadecimal numbers.
        /// </summary>
        /// <param name="key">The String to separate</param>
        /// <summary>
        /// Separates the contents of the specified System.String object into an array of hexadecimal
        /// values with every cell/byte containing two hexadecimal numbers.
        /// </summary>
        /// <param name="key">The String to separate</param>
        private void separateKeyValues(String key)
        {
            int colIndex = 0, rowIndex = 0;
            for (int i = 0; i < key.Length; i += 2)
            {
                this.initialKey[rowIndex % 4, colIndex % 4] = Convert.ToByte(Char.ToString(key[i]) + Char.ToString(key[i + 1]), 16);
                rowIndex++;
                if (rowIndex % 4 == 0)
                    colIndex++;
            }
        }
        /// <summary>
        /// Performs the key scheduling process in AES-128 to produce 11 keys each a 16-byte length.
        /// </summary>
        private void ExpandKey()   //Passed Successfully
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
                    key[i] = this.initialKey[index % 4, col]; //Converts a string object into an array of bytes.
                    index++;
                }
                col++;
                words[iter] = BitConverter.ToUInt32(key, 0);
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
        /// Represents the encryotion routine in AES-128 performs four main steps in 10 rounds of encrytping the same block 
        /// of data.
        /// </summary>
        /// <param name="text">The text to encrypt.</param>
        /// <returns></returns>
        internal String Encrypt(String block)
        {
            //First convert the 128-bits string into state matrix
            int colIndex = 0, rowIndex = 0;
            byte[,] state = new byte[4, 4];
            for (int i = 0; i < block.Length; i += 2)
            {
                state[rowIndex % 4, colIndex % 4] = Convert.ToByte(Char.ToString(block[i]) + Char.ToString(block[i + 1]), 16);
                //state[rowIndex % 4, colIndex % 4] = block[i];
                rowIndex++;
                if (rowIndex % 4 == 0)
                    colIndex++;
            }
            //Add initial key aka, the whitening step
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[i, j] = Convert.ToByte(state[i, j] ^ this.initialKey[i, j]);
                }
            }
            //Start the rounds of the algorithm
            int round = 0;
            while (round < 10)
            {
                state = SubByte(state);
                state = ShiftRow(state);
                if (round != 9)
                {
                    state = MixColumns(state);
                }
                state = AddRoundKey(state, round);
                round++;
            }
            StringBuilder encrypted = new StringBuilder();
            for (int i = 0; i < state.GetLength(0); i++)
                for (int j = 0; j < state.GetLength(1); j++)
                {
                    byte[] temp = { state[i, j] };
                    encrypted.Append(BitConverter.ToString(temp));
                }
            return encrypted.ToString();
        }
        /// <summary>
        /// Replaces every cell of the specified hexadecimal System.String two dimensional array
        /// according ot the pre-defined S-Box in AES.
        /// </summary>
        /// <param name="state">The two dimensional array of hexadecimal strings.</param>
        /// <returns>The two dimensional array after substitution.</returns>
        private byte[,] SubByte(byte[,] state)    //Passed unit test successfully.
        {
            for (int i = 0; i < state.GetLength(0); i++)
            {
                for (int j = 0; j < state.GetLength(1); j++)
                {
                    byte[] cell = { state[i, j] };
                    String val = BitConverter.ToString(cell);
                    byte[] sub = { this.SBox[Convert.ToByte(val.Substring(0, 1), 16), 
                                         Convert.ToByte(val.Substring(1), 16)] };
                    state[i, j] = sub[0];
                }
            }
            return state;
        }
        /// <summary>
        /// Applies a row-dependent byte-level shift-to-left to each row of the specified System.String two dimensional array.
        /// </summary>
        /// <param name="state">The two dimensional array to shift.</param>
        /// <returns></returns>
        private byte[,] ShiftRow(byte[,] state) //Passed unit testing
        {
            //We need to define another matrix since the shift is not fixed.
            byte[,] shifted = new byte[4, 4];
            for (int k = 0; k < 4; k++)
                shifted[0, k] = state[0, k];
            for (int round = 1; round < 4; round++)
            {
                //Find which element would be placed at cell [round,0] and store its value.
                var rep = state[round, round];  //correct
                for (int i = 0; i < 4; i++)
                {
                    //Add % to allow cyclic shift-to-left which depends on the index of the current row indicated by round.
                    shifted[round, i] = state[round, (i + round) % 4];
                }
                shifted[round, 0] = rep;
                if (round == 3)
                    break;
            }
            return shifted;
        }
        /// <summary>
        /// Multiplies the specifed two dimensional array of System.String objects with the pre-defined matrix in GF(256)
        /// to deliver diffusion to the encryption process.
        /// </summary>
        /// <param name="state">The current state of the input file/text.</param>
        /// <returns></returns>
        private byte[,] MixColumns(byte[,] state)  //Passed unit test successfully.
        {
            byte[,] mixed = new byte[state.GetLength(0), state.GetLength(1)];
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
                        if (this.mixingMatrix[i, k] == 0x03)
                        {
                            //If the cuurent multiplier is 0x03 we need to distribute the multiplication over addition
                            //i.e,0x03*x= x + 0x02*x
                            //Note applying XOR after or before MulInGF would not change the result.
                            result = Convert.ToByte(MulInGF(StringParser.ToBits(state[k, j])) ^ (state[k, j]));
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
                                result = state[k, j];
                            }
                        sum[0] = Convert.ToByte(result ^ sum[0]);
                    }
                    mixed[i, j] = sum[0];
                }
            }
            return mixed;
        }
        /// <summary>
        /// Applies a non-cyclic shift-to-left to the specified System.Byte array and replaces the right-most element
        /// with zero in order to perform multiplying in GF(2^8) by the constant 0x1B if neccessary.
        /// </summary>
        /// <param name="bits">An array of 0s and 1s.</param>
        /// <returns>The corresponding hexadecimal value after shifting and multiplying.</returns>
        private byte MulInGF(byte[] bits)    //Passed unit testing.
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
        private byte[,] AddRoundKey(byte[,] state, int round)
        {
            byte[,] stateValues = new byte[state.GetLength(0), state.GetLength(1)];
            //separate the UInt32 round key values into 16 bytes to eable bitwise XOR operation.
            byte[,] roundKey = new byte[state.GetLength(0), state.GetLength(1)];
            int index = 0, colIndex = 0;
            while (index < 4)
            {
                byte[] temp = BitConverter.GetBytes(this.roundKeys[round, index]);
                for (int i = 0; i < temp.Length; i++)
                {
                    roundKey[i, colIndex] = temp[i];//filling column by column
                }
                index++;
                colIndex++;
            }
            //Perform the Bitwise XOR operation on the element of the state matrix.
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    byte[] res = { Convert.ToByte(state[i, j] ^ roundKey[i, j]) };
                    state[i, j] = res[0];
                }
            }
            return state;
        }
        /// <summary>
        /// The Decryption routine applied in AES-128.
        /// </summary>
        /// <param name="cipheredText"></param>
        /// <returns></returns>
        internal String Decrypt(String cipheredText)
        {
            //First convert the 128-bits string into state matrix
            int colIndex = 0, rowIndex = 0;
            byte[,] state = new byte[4, 4];
            for (int i = 0; i < cipheredText.Length; i += 2)
            {
                state[rowIndex, colIndex % 4] = Convert.ToByte(Char.ToString(cipheredText[i]) + Char.ToString(cipheredText[i + 1]), 16);
                colIndex++;
                if (colIndex % 4 == 0)
                    rowIndex++;
            }
            //Add round key #10 aka, the inverse whitening step
            state = AddRoundKey(state, 9);
            int round = 8;
            while (round >= 0)
            {
                state = InvShiftRows(state);
                state = InvSubByte(state);
                state = AddRoundKey(state, round);
                state = InvMixColumns(state);
                round--;
            }
            //Apply the last add round key with the inital key
            state = InvShiftRows(state);
            state = InvSubByte(state);
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    byte[] res = { Convert.ToByte(state[i, j] ^
                                         this.initialKey[i, j]) };
                    state[i, j] = res[0];
                }
            }
            StringBuilder decrypted = new StringBuilder();
            for (int i = 0; i < state.GetLength(0); i++)
                for (int j = 0; j < state.GetLength(1); j++)
                {
                    byte[] temp = { state[j, i] };
                    decrypted.Append(BitConverter.ToString(temp));
                }
            return decrypted.ToString();
        }
        /// <summary>
        /// Applies a circular row-dependent byte-level shift-to-right to each row of the specified System.String 
        /// two dimensional array.
        /// </summary>
        /// <param name="state">The two dimensional array to shift.</param>
        /// <returns></returns>
        private byte[,] InvShiftRows(byte[,] state)
        {
            byte[,] shifted = new byte[4, 4];
            //The first row is coppied without any change.
            for (int k = 0; k < 4; k++)
                shifted[0, k] = state[0, k];
            for (int round = 1; round < 4; round++)
            {
                for (int i = 0; i < 4; i++)
                {
                    shifted[round, i] = state[round, ((4 - round) + i) % 4];
                }
            }
            return shifted;
        }
        /// <summary>
        /// Applies the inverse multiplication step in GF2^8 on the 128-bits block in the decryption routine.
        /// </summary>
        /// <param name="state"></param>
        ///<returns></returns>
        private byte[,] InvMixColumns(byte[,] state)
        {
            byte[,] mixed = new byte[state.GetLength(0), state.GetLength(1)];
            byte result = 0;
            byte[] sum = new byte[1];
            //Add 3 for-loops in order to find the matrices multiplications.
            for (int i = 0; i < this.invMixingMat.GetLength(0); i++)
            {
                //First loop to iterate over the rows of the resulted matrix,at each iteration reset sum to 0.
                for (int j = 0; j < state.GetLength(1); j++)
                {
                    //Second loop to iterate over the columns of the state marix
                    sum[0] = 0x00;
                    for (int k = 0; k < this.invMixingMat.GetLength(1); k++)
                    {
                        byte[] cell = { state[k, j] };
                        String val = BitConverter.ToString(cell);
                        result = 0x00;
                        if (this.invMixingMat[i, k] == 0x0E)
                        {

                            result = this.mulBy0E[Convert.ToByte(val.Substring(0, 1), 16), Convert.ToByte(val.Substring(1), 16)];
                        }
                        else
                            if (this.invMixingMat[i, k] == 0x0B)
                            {
                                result = this.mulBy0B[Convert.ToByte(val.Substring(0, 1), 16), Convert.ToByte(val.Substring(1), 16)];
                            }
                            else
                                if (this.invMixingMat[i, k] == 0x0D)
                                {
                                    result = this.mulBy0D[Convert.ToByte(val.Substring(0, 1), 16), Convert.ToByte(val.Substring(1), 16)];
                                }
                                else
                                {
                                    //The multiplier is hence 0x09.
                                    result = this.mulBy09[Convert.ToByte(val.Substring(0, 1), 16), Convert.ToByte(val.Substring(1), 16)];
                                }
                        sum[0] = Convert.ToByte(result ^ sum[0]);
                    }
                    mixed[i, j] = sum[0];
                }
            }
            return mixed;
        }
        /// <summary>
        /// Applies the inverse byte substitution operation in decrypt routine on the ciphered 128-bits block.
        /// </summary>
        /// <param name="state">The current block of the ciphered file.</param>
        /// <returns>128-bits block represented as 2-dimensional matrix of substituted bytes</returns>
        private byte[,] InvSubByte(byte[,] state)    //Passed unit test successfully.
        {
            for (int i = 0; i < state.GetLength(0); i++)
            {
                for (int j = 0; j < state.GetLength(1); j++)
                {
                    byte[] cell = { state[i, j] };
                    String val = BitConverter.ToString(cell);
                    byte[] sub = { this.invSBox[Convert.ToByte(val.Substring(0, 1), 16), Convert.ToByte(val.Substring(1), 16)] };
                    state[i, j] = sub[0];
                }
            }
            return state;
        }
        ///<summary>
        ///Represents the encryption routine in AES-128.
        ///</summary>
        ///<param name="block">The 16-bytes block to encrypt.</param>
        ///<returns></returns>
        internal byte[] Encrypt(byte[] block)
        {
            //First convert the 128-bits string into state matrix
            int colIndex = 0, rowIndex = 0;
            byte[,] state = new byte[4, 4];
            for (int i = 0; i < block.Length; i++)
            {
                state[rowIndex % 4, colIndex % 4] = block[i];
                rowIndex++;
                if (rowIndex % 4 == 0)
                    colIndex++;
            }
            //Add initial key aka, the whitening step
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[i, j] = Convert.ToByte(state[i, j] ^ this.initialKey[i, j]);
                }
            }
            //Start the rounds of the algorithm
            int round = 0;
            while (round < 10)
            {
                state = SubByte(state);
                state = ShiftRow(state);
                if (round != 9)
                {
                    state = MixColumns(state);
                }
                state = AddRoundKey(state, round);
                round++;
            }
            byte[] encrypted = new byte[16];
            int index = 0;
            for (int i = 0; i < state.GetLength(0); i++)
                for (int j = 0; j < state.GetLength(1); j++)
                {
                    encrypted[index] = state[i, j];
                    index++;
                }
            return encrypted;
        }
        ///<summary>
        ///Represents the decryption routine in AES-128.
        ///</summary>
        ///<param name="block">The 16-bytes block to decrypt.</param>
        ///<returns></returns>
        internal byte[] Decrypt(byte[] cipheredBlock)
        {
            //First convert the 128-bits string into state matrix
            int colIndex = 0, rowIndex = 0;
            byte[,] state = new byte[4, 4];
            for (int i = 0; i < cipheredBlock.Length; i++)
            {
                state[rowIndex, colIndex % 4] = cipheredBlock[i];
                colIndex++;
                if (colIndex % 4 == 0)
                    rowIndex++;
            }
            //Add round key #10 aka, the inverse whitening step
            state = AddRoundKey(state, 9);
            int round = 8;
            while (round >= 0)
            {
                state = InvShiftRows(state);
                state = InvSubByte(state);
                state = AddRoundKey(state, round);
                state = InvMixColumns(state);
                round--;
            }
            //Apply the last add round key with the inital key
            state = InvShiftRows(state);
            state = InvSubByte(state);
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    byte[] res = { Convert.ToByte(state[i, j] ^
                                         this.initialKey[i, j]) };
                    state[i, j] = res[0];
                }
            }
            byte[] decrypted = new byte[16];
            int index = 0;
            for (int i = 0; i < state.GetLength(0); i++)
                for (int j = 0; j < state.GetLength(1); j++)
                {
                    decrypted[index] = state[j, i];
                    index++;
                }
            return decrypted;
        }
    }
}
