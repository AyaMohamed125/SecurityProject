using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        private static string[] SBOX = {
            "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76",
            "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0",
            "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15",
            "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75",
            "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84",
            "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF",
            "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8",
            "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2",
            "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73",
            "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB",
            "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79",
            "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08",
            "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A",
            "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E",
            "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF",
            "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"
        };
        private static byte[] iSBOX = {
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
        };
        public static string[] mixCols = {
        "02", "03", "01", "01",
        "01", "02", "03", "01",
        "01", "01", "02", "03",
        "03", "01", "01", "02"
        };
        public static string[] Rcon = {
        "01","02","04","08","10","20","40","80","1B","36" ,"00","00","00","00","00","00","00","00","00","00" ,
        "00","00","00","00","00","00","00","00","00","00" ,"00","00","00","00","00","00","00","00","00","00"
        };

        public static string[] EditRow(string[] m, int j)
        {
            string[] matrix = new string[4];
            for (int i = 0; i < 4; i++)
                matrix[i] = m[(i + j) % 4];

            return matrix;
        }
        public static string[] Edit_Column(string[,] x)
        {
            string[] sub_array = new string[4];
            for (int i = 0; i < 4; i++)
                sub_array[i] = x[(i + 1) % 4, 3];

            return sub_array;
        }
        public static string[,] EditLastColumn(string[,] m)
        {
            string[,] matrix = new string[4, 1];
            for (int i = 0; i < 4; i++)
                matrix[i, 0] = m[(i + 1) % 4, 0];
            return matrix;
        }
        public static string EditMatrixBinaryShift(string x)
        {
            string sub_array = "";
            for (int i = 0; i < x.Length; i++)
                sub_array = sub_array + x[(i + 1) % x.Length];

            return sub_array;
        }
        public static string[,] Shift_Rows(string[,] matrix)
        {
            int row = 0;
            string[] x = new string[4];
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                    x[i] = matrix[row, i];

                x = EditRow(x, j);

                for (int z = 0; z < 4; z++)
                    matrix[row, z] = x[z];

                row++;
            }
            return matrix;
        }
        public static string[,] Generate_Matrix(string x)
        {
            string[,] key_matrix = new string[4, 4];
            int counter = 2;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    key_matrix[j, i] = Convert.ToString(x[counter]);
                    counter++;
                    key_matrix[j, i] += Convert.ToString(x[counter]);
                    counter++;
                }
            }
            return key_matrix;
        }
        public static string To_Binary(string str)
        {
            //convert from hexa to binary
            str = Convert.ToString(Convert.ToInt64(str, 16), 2);
            if (str.Length < 8)
                str = new string('0', 8 - str.Length) + str;
            return str;
        }
        public static string To_Hexa(string str)
        {
            //convert from Binary to Hexa
            string res = "";
            string test = "";
            for (int i = 0; i < str.Length; i += 4)
            {
                if (i < str.Length && i + 1 < str.Length && i + 2 < str.Length && i + 3 < str.Length)
                {
                    res = str[i].ToString() + str[i + 1].ToString() + str[i + 2].ToString() + str[i + 3].ToString();
                    res = Convert.ToInt32(res, 2).ToString();

                }
                if (res.Length != 1)
                {
                    if (res == "10")
                        res = "A";
                    else if (res == "11")
                        res = "B";
                    else if (res == "12")
                        res = "C";
                    else if (res == "13")
                        res = "D";
                    else if (res == "14")
                        res = "E";
                    else
                        res = "F";
                }
                else
                    res = res;
                test = test + res;
            }
            //res = Convert.ToString(Convert.ToInt64(str, 16), 2);
            return test;
        }
        public static string RoundKey(string str1, string str2)
        {
            string result = "";
            for (int i = 0; i < str2.Length; i++)
            {
                if (i < str1.Length && str1[i] == str2[i])
                    result += '0';
                else
                    result += '1';
            }
            return result;
        }
        public static int whereBox(string a)
        {
            int res = 0;
            if (a.Length == 2)
            {
                int char1 = Convert.ToInt32(a[0].ToString(), 16);
                int char2 = Convert.ToInt32(a[1].ToString(), 16);
                res = char1 * 16 + char2;
            }

            return res;
        }

        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            string cipherText = "0x";
            string[,] plainText_matrix = Generate_Matrix(plainText);
            string[,] key_matrix = Generate_Matrix(key);
            string[,] plainText_Binary = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plainText_Binary[i, j] = To_Binary(plainText_matrix[i, j]);
                }
            }

            int r = 0;
            int cou = 0;
            int count = 0;
            int counter = 0;
            string roundMat = "";
            string roundMat1 = "";
            string totalStr1 = "";
            string totalStr2 = "";
            string totalSt = "";
            string[,] matFainal = new string[4, 4];
            string[,] colMatrix = new string[4, 1];
            string[,] rconMatrix = new string[4, 1];
            string[,] rcon = new string[4, 10];
            string[,] lastCol = new string[4, 1];
            string[,] Key_Binary = new string[4, 4];
            string[,] stateRounded = new string[4, 4];
            string[,] totalColMatrix = new string[4, 1];
            string[,] sBoxMatrixChanger = new string[4, 4];


            //round key1
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Key_Binary[i, j] = To_Binary(key_matrix[i, j]);
                    stateRounded[i, j] = RoundKey(Key_Binary[i, j], plainText_Binary[i, j]);
                    stateRounded[i, j] = (To_Hexa(stateRounded[i, j])).ToString();

                }
            }

            for (int i = 0; i < 9; i++)
            {
                //SubBytes

                for (int j = 0; j < 4; j++)
                    for (int q = 0; q < 4; q++)
                        sBoxMatrixChanger[j, q] = SBOX[whereBox(stateRounded[j, q])];

                // Shift Rows
                sBoxMatrixChanger = Shift_Rows(sBoxMatrixChanger);

                //Mix Columns
                counter = 0;
                int col = 0;
                string[,] maxCol = new string[4, 4];
                string[,] sBoxMatrixChangerBinary = new string[4, 4];

                for (int o = 0; o < 4; o++)
                    for (int j = 0; j < 4; j++)
                        sBoxMatrixChangerBinary[o, j] = To_Binary(sBoxMatrixChanger[o, j]);

                //Multiplying two matrices of hexa numbers
                for (int j = 0; j < 4; j++)
                {
                    counter = 0;

                    for (int q = 0; q < 4; q++)
                    {
                        for (int w = 0; w < 4; w += 2)
                        {
                            totalStr2 = totalStr1;

                            if (counter < mixCols.Length && w + 1 < 4 && counter + 1 < mixCols.Length)
                            {
                                string str1 = sBoxMatrixChangerBinary[w, j];
                                string str2 = sBoxMatrixChangerBinary[w + 1, j];


                                string mixCol = mixCols[counter];
                                string mixCol1 = mixCols[counter + 1];
                                counter += 2;

                                if (mixCol == "02")
                                {
                                    str1 = EditMatrixBinaryShift(str1);

                                    if (str1[7].Equals('1'))
                                    {
                                        str1 = str1.Remove(7, 1);
                                        str1 = str1.Insert(7, "0");

                                        string st = "00011011";
                                        str1 = RoundKey(str1, st);

                                    }
                                }

                                if (mixCol1 == "02")
                                {
                                    str2 = EditMatrixBinaryShift(str2);
                                    if (str2[7].Equals('1'))
                                    {
                                        str2 = str2.Remove(7, 1);
                                        str2 = str2.Insert(7, "0");
                                        string st = "00011011";
                                        str2 = RoundKey(str2, st);
                                    }
                                }

                                if (mixCol == "03")
                                {
                                    string editStr1 = "";
                                    // once "01"
                                    editStr1 = str1;
                                    // once "02"
                                    str1 = EditMatrixBinaryShift(str1);
                                    if (str1[7].Equals('1'))
                                    {
                                        str1 = str1.Remove(7, 1);
                                        str1 = str1.Insert(7, "0");
                                        string st = "00011011";
                                        str1 = RoundKey(str1, st);
                                    }

                                    str1 = RoundKey(str1, editStr1);
                                }

                                if (mixCol1 == "03")
                                {
                                    string editStr2 = "";
                                    editStr2 = str2;
                                    str2 = EditMatrixBinaryShift(str2);
                                    if (str2[7].Equals('1'))
                                    {
                                        str2 = str2.Remove(7, 1);
                                        str2 = str2.Insert(7, "0");
                                        string st = "00011011";
                                        str2 = RoundKey(str2, st);
                                    }

                                    str2 = RoundKey(str2, editStr2);
                                }

                                totalStr1 = RoundKey(str1, str2);

                            }

                            totalSt = RoundKey(totalStr1, totalStr2);

                        }
                        if (col < 4)
                            maxCol[q, col] = To_Hexa(totalSt);
                    }
                    col++;

                }

                //AddRooundKey
                for (int p = 0; p < 4; p++)
                    lastCol[p, 0] = key_matrix[p, 3];

                lastCol = EditLastColumn(lastCol);
                for (int p = 0; p < 4; p++)
                    lastCol[p, 0] = SBOX[whereBox(lastCol[p, 0])];

                // full Matrix Rcon
                for (int p = 0; p < 4; p++)
                {
                    for (int w = 0; w < 10; w++)
                    {
                        if (count < Rcon.Length)
                        {
                            rcon[p, w] = Rcon[count];
                            count++;
                        }
                    }
                }


                r = 0;
                for (int p = 0; p < 4; p++)
                {
                    if (cou < 10)
                    {
                        colMatrix[p, 0] = key_matrix[p, 0];
                        rconMatrix[p, 0] = rcon[p, cou];
                    }

                }

                for (int p = 0; p < 4; p++)
                {
                    string binaryColMatrix = To_Binary(colMatrix[p, 0]);
                    string binaryLastCol = To_Binary(lastCol[p, 0]);
                    string binaryRconMatrix = To_Binary(rconMatrix[p, 0]);
                    roundMat = RoundKey(binaryColMatrix, binaryLastCol);
                    roundMat1 = RoundKey(roundMat, binaryRconMatrix);
                    key_matrix[p, r] = To_Hexa(roundMat1);
                }
                r = 1;
                for (int p = 0; p < 4; p++)
                    colMatrix[p, 0] = key_matrix[p, r];
                for (int p = 0; p < 4; p++)
                {
                    string binaryColMatrix = To_Binary(colMatrix[p, 0]);
                    string binarylastCol = To_Binary(key_matrix[p, 0]);
                    roundMat = RoundKey(binaryColMatrix, binarylastCol);
                    key_matrix[p, r] = To_Hexa(roundMat);

                }

                r = 2;
                for (int p = 0; p < 4; p++)
                    colMatrix[p, 0] = key_matrix[p, 2];
                for (int p = 0; p < 4; p++)
                {
                    string binaryColMatrix = To_Binary(colMatrix[p, 0]);
                    string binarylastCol = To_Binary(key_matrix[p, 1]);
                    roundMat = RoundKey(binaryColMatrix, binarylastCol);
                    key_matrix[p, r] = To_Hexa(roundMat);

                }

                r = 3;
                for (int p = 0; p < 4; p++)
                    colMatrix[p, 0] = key_matrix[p, r];
                for (int p = 0; p < 4; p++)
                {
                    string binaryColMatrix = To_Binary(colMatrix[p, 0]);
                    string binarylastCol = To_Binary(key_matrix[p, 2]);
                    roundMat = RoundKey(binaryColMatrix, binarylastCol);
                    key_matrix[p, r] = To_Hexa(roundMat);

                }

                //round key
                for (int g = 0; g < 4; g++)
                {
                    for (int e = 0; e < 4; e++)
                    {
                        string s1 = To_Binary(maxCol[e, g]);
                        string s2 = To_Binary(key_matrix[e, g]);
                        string totalS = RoundKey(s1, s2);
                        stateRounded[e, g] = To_Hexa(totalS);

                    }
                }

                cou++;

            }

            //SubBytes

            for (int j = 0; j < 4; j++)
                for (int q = 0; q < 4; q++)
                    sBoxMatrixChanger[j, q] = SBOX[whereBox(stateRounded[j, q])];

            // Shift Rows
            sBoxMatrixChanger = Shift_Rows(sBoxMatrixChanger);

            //AddRooundKey
            for (int p = 0; p < 4; p++)
                lastCol[p, 0] = key_matrix[p, 3];

            lastCol = EditLastColumn(lastCol);
            for (int p = 0; p < 4; p++)
                lastCol[p, 0] = SBOX[whereBox(lastCol[p, 0])];

            // full Matrix Rcon
            count = 0;
            for (int p = 0; p < 4; p++)
            {
                for (int w = 0; w < 10; w++)
                {
                    if (count < Rcon.Length)
                    {
                        rcon[p, w] = Rcon[count];
                        count++;
                    }
                }
            }

            //Multiplying two matrices of hexa numbers
            r = 0;
            for (int p = 0; p < 4; p++)
            {
                colMatrix[p, 0] = key_matrix[p, 0];
                rconMatrix[p, 0] = rcon[p, 9];
            }

            for (int p = 0; p < 4; p++)
            {
                string binaryColMatrix = To_Binary(colMatrix[p, 0]);
                string binaryLastCol = To_Binary(lastCol[p, 0]);
                string binaryRconMatrix = To_Binary(rconMatrix[p, 0]);
                roundMat = RoundKey(binaryColMatrix, binaryLastCol);
                roundMat1 = RoundKey(roundMat, binaryRconMatrix);
                key_matrix[p, r] = To_Hexa(roundMat1);
            }
            r = 1;
            for (int p = 0; p < 4; p++)
                colMatrix[p, 0] = key_matrix[p, r];
            for (int p = 0; p < 4; p++)
            {
                string binaryColMatrix = To_Binary(colMatrix[p, 0]);
                string binarylastCol = To_Binary(key_matrix[p, 0]);
                roundMat = RoundKey(binaryColMatrix, binarylastCol);
                key_matrix[p, r] = To_Hexa(roundMat);

            }

            r = 2;
            for (int p = 0; p < 4; p++)
                colMatrix[p, 0] = key_matrix[p, 2];
            for (int p = 0; p < 4; p++)
            {
                string binaryColMatrix = To_Binary(colMatrix[p, 0]);
                string binarylastCol = To_Binary(key_matrix[p, 1]);
                roundMat = RoundKey(binaryColMatrix, binarylastCol);
                key_matrix[p, r] = To_Hexa(roundMat);

            }

            r = 3;
            for (int p = 0; p < 4; p++)
                colMatrix[p, 0] = key_matrix[p, r];
            for (int p = 0; p < 4; p++)
            {
                string binaryColMatrix = To_Binary(colMatrix[p, 0]);
                string binarylastCol = To_Binary(key_matrix[p, 2]);
                roundMat = RoundKey(binaryColMatrix, binarylastCol);
                key_matrix[p, r] = To_Hexa(roundMat);

            }

            //round key
            for (int g = 0; g < 4; g++)
            {
                for (int e = 0; e < 4; e++)
                {
                    string s1 = To_Binary(sBoxMatrixChanger[e, g]);
                    string s2 = To_Binary(key_matrix[e, g]);
                    string totalS = RoundKey(s1, s2);
                    stateRounded[e, g] = To_Hexa(totalS);

                }
            }

            for (int g = 0; g < 4; g++)
            {
                for (int j = 0; j < 4; j++)
                {
                    cipherText += stateRounded[j, g];
                }
            }

            return cipherText;
        }
    }
}
