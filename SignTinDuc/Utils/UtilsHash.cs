using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SignTinDuc
{
    public class UtilsHash
    {
        public static string ComputeHashByte(string strHashAlgorithm, byte[] data, out byte[] bytes)
        {
            bytes = (byte[])null;
            string hashByte;
            switch (strHashAlgorithm.ToUpper())
            {
                case "MD5":
                    hashByte = UtilsHash.ComputeArrMD5Hash(data, out bytes);
                    break;
                case "SHA1":
                    hashByte = UtilsHash.ComputeArrSHA1Hash(data, out bytes);
                    break;
                case "SHA256":
                    hashByte = UtilsHash.ComputeArrSHA256Hash(data, out bytes);
                    break;
                case "SHA384":
                    hashByte = UtilsHash.ComputeArrSHA384Hash(data, out bytes);
                    break;
                case "SHA512":
                    hashByte = UtilsHash.ComputeArrSHA512Hash(data, out bytes);
                    break;
                default:
                    hashByte = "Kiểu ký " + strHashAlgorithm + " không hợp lệ";
                    break;
            }
            return hashByte;
        }

        public static string ComputeArrSHA256Hash(byte[] data, out byte[] dataHash)
        {
            dataHash = (byte[])null;
            try
            {
                SHA256Managed shA256Managed = new SHA256Managed();
                dataHash = shA256Managed.ComputeHash(data);
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }

        public static string ComputeArrMD5Hash(byte[] data, out byte[] dataHash)
        {
            dataHash = (byte[])null;
            try
            {
                MD5 md5 = MD5.Create();
                dataHash = md5.ComputeHash(data);
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }

        public static string ComputeArrSHA1Hash(byte[] data, out byte[] dataHash)
        {
            dataHash = (byte[])null;
            try
            {
                SHA1Managed shA1Managed = new SHA1Managed();
                dataHash = shA1Managed.ComputeHash(data);
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }

        public static string ComputeArrSHA384Hash(byte[] data, out byte[] dataHash)
        {
            dataHash = (byte[])null;
            try
            {
                SHA384Managed shA384Managed = new SHA384Managed();
                dataHash = shA384Managed.ComputeHash(data);
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }

        public static string ComputeArrSHA512Hash(byte[] data, out byte[] dataHash)
        {
            dataHash = (byte[])null;
            try
            {
                SHA512Managed shA512Managed = new SHA512Managed();
                dataHash = shA512Managed.ComputeHash(data);
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }

        public static string StreamToByteArray(Stream input, out byte[] arrData)
        {
            arrData = (byte[])null;
            try
            {
                byte[] buffer = new byte[16384];
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    int count;
                    while ((count = input.Read(buffer, 0, buffer.Length)) > 0)
                        memoryStream.Write(buffer, 0, count);
                    arrData = memoryStream.ToArray();
                }
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }
    }

}
