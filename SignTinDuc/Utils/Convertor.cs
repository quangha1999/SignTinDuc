using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;
using System.Xml;
using Newtonsoft.Json;

namespace SignTinDuc
{
    internal static class Convertor
    {
        public static string ObjectToJson(object obj, out string value)
        {
            value = "";
            try
            {
                value = JsonConvert.SerializeObject(obj);
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }

        public static string GetBytes(string data, out byte[] bytes)
        {
            string bytes1 = "";
            bytes = (byte[])null;
            try
            {
                bytes = Encoding.UTF8.GetBytes(data);
            }
            catch (Exception ex)
            {
                bytes1 = ex.ToString();
            }
            return bytes1;
        }

        public static string GetFrameFromString(
          string Message,
          out byte[] response,
          Convertor.EOpcodeType Opcode = Convertor.EOpcodeType.Text)
        {
            response = (byte[])null;
            try
            {
                byte[] bytes = Encoding.Default.GetBytes(Message);
                byte[] numArray = new byte[10];
                long length = (long)bytes.Length;
                numArray[0] = (byte)(128 + Opcode);
                long num;
                if (length <= 125L)
                {
                    numArray[1] = (byte)length;
                    num = 2L;
                }
                else if (length >= 126L && length <= (long)ushort.MaxValue)
                {
                    numArray[1] = (byte)126;
                    numArray[2] = (byte)((ulong)(length >> 8) & (ulong)byte.MaxValue);
                    numArray[3] = (byte)((ulong)length & (ulong)byte.MaxValue);
                    num = 4L;
                }
                else
                {
                    numArray[1] = (byte)127;
                    numArray[2] = (byte)((ulong)(length >> 56) & (ulong)byte.MaxValue);
                    numArray[3] = (byte)((ulong)(length >> 48) & (ulong)byte.MaxValue);
                    numArray[4] = (byte)((ulong)(length >> 40) & (ulong)byte.MaxValue);
                    numArray[5] = (byte)((ulong)(length >> 32) & (ulong)byte.MaxValue);
                    numArray[6] = (byte)((ulong)(length >> 24) & (ulong)byte.MaxValue);
                    numArray[7] = (byte)((ulong)(length >> 16) & (ulong)byte.MaxValue);
                    numArray[8] = (byte)((ulong)(length >> 8) & (ulong)byte.MaxValue);
                    numArray[9] = (byte)((ulong)length & (ulong)byte.MaxValue);
                    num = 10L;
                }
                response = new byte[num + length];
                long index1 = 0;
                for (long index2 = 0; index2 < num; ++index2)
                {
                    response[index1] = numArray[index2];
                    ++index1;
                }
                for (long index3 = 0; index3 < length; ++index3)
                {
                    response[index1] = bytes[index3];
                    ++index1;
                }
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }

        public static string Base64StringToBytes(string base64, out byte[] value)
        {
            string bytes = "";
            value = (byte[])null;
            try
            {
                value = Convert.FromBase64String(base64);
            }
            catch (Exception ex)
            {
                bytes = ex.ToString();
            }
            return bytes;
        }

        public static string ByteArrToBase64String(byte[] byteArr, out string value)
        {
            string base64String = "";
            value = (string)null;
            if (byteArr == null)
                return "Error: Object is null @ByteArrToBase64String";
            try
            {
                value = Convert.ToBase64String(byteArr);
            }
            catch (Exception ex)
            {
                base64String = ex.ToString();
            }
            return base64String;
        }

        public static string GetDecodedData(byte[] buffer, int length, out string data)
        {
            data = "";
            try
            {
                byte num1 = buffer[1];
                int count = 0;
                int num2 = 0;
                int index1 = 0;
                if ((int)num1 - 128 <= 125)
                {
                    count = (int)num1 - 128;
                    index1 = 2;
                    num2 = count + 6;
                }
                if ((int)num1 - 128 == 126)
                {
                    count = (int)BitConverter.ToInt16(new byte[2]
                    {
            buffer[3],
            buffer[2]
                    }, 0);
                    index1 = 4;
                    num2 = count + 8;
                }
                if ((int)num1 - 128 == (int)sbyte.MaxValue)
                {
                    count = (int)BitConverter.ToInt64(new byte[8]
                    {
            buffer[9],
            buffer[8],
            buffer[7],
            buffer[6],
            buffer[5],
            buffer[4],
            buffer[3],
            buffer[2]
                    }, 0);
                    index1 = 10;
                    num2 = count + 14;
                }
                if (num2 > length)
                    throw new Exception("The buffer length is small than the data length");
                byte[] numArray = new byte[4]
                {
          buffer[index1],
          buffer[index1 + 1],
          buffer[index1 + 2],
          buffer[index1 + 3]
                };
                int index2 = index1 + 4;
                int num3 = 0;
                for (int index3 = index2; index3 < num2; ++index3)
                {
                    buffer[index3] = (byte)((uint)buffer[index3] ^ (uint)numArray[num3 % 4]);
                    ++num3;
                }
                if (count > 0)
                {
                    data = Encoding.ASCII.GetString(buffer, index2, count);
                }

            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }

        public static string Serialize(object o)
        {
            using (StringWriter stringWriter = new StringWriter())
            {
                new XmlSerializer(o.GetType()).Serialize((TextWriter)stringWriter, o);
                return stringWriter.ToString();
            }
        }

        public static string JsonToObject<T>(object data, out T obj) where T : class
        {
            obj = default(T);
            try
            {
                obj = JsonConvert.DeserializeObject<T>(Convert.ToString(data));
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }

        public static string Base64Decode(string base64EncodedData, out string plainText)
        {
            plainText = (string)null;
            try
            {
                byte[] bytes = Convert.FromBase64String(base64EncodedData);
                plainText = Encoding.UTF8.GetString(bytes);
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }

        public static string Base64Encode(string plainText, out string value)
        {
            value = (string)null;
            try
            {
                byte[] bytes = Encoding.UTF8.GetBytes(plainText);
                value = Convert.ToBase64String(bytes);
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }

        public static string LoadXML(string ContentXML, out XmlDocument xmlDocument)
        {
            xmlDocument = new XmlDocument();
            try
            {
                xmlDocument.LoadXml(ContentXML);
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }

        public enum EOpcodeType
        {
            Fragment = 0,
            Text = 1,
            Binary = 2,
            ClosedConnection = 8,
            Ping = 9,
            Pong = 10, // 0x0000000A
        }
    }
}
