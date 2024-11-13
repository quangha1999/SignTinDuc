using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SignTinDuc
{
    public static class Log
    {
        public static string MessageForUser = "[MessageForUser] ";
        public static string MoreDetailLog = "[MoreDetailLog] ";

        public static Result ToMNFResultError<T>(
          string msg,
          ResultStatus resultStatus,
          string prefixLog,
          T parameters)
          where T : class
        {
            return Log.ProcessAndToResultError<T>(Log.ToMNFMessage(msg, prefixLog), resultStatus, parameters);
        }

        public static Result ToMNFResultError(string msg, ResultStatus resultStatus, string prefixLog = "")
        {
            return Log.ProcessAndToResultError(Log.ToMNFMessage(msg, prefixLog), resultStatus);
        }

        public static Result ToUMNFResultError<T>(string msg, ResultStatus resultStatus, T parameters) where T : class
        {
            return Log.ProcessAndToResultError<T>(Log.ToUMMessage(msg, ""), resultStatus, parameters);
        }

        public static Result ToUMNFResultError<T>(
          string msg,
          ResultStatus resultStatus,
          string prefixLog,
          T parameters)
          where T : class
        {
            return Log.ProcessAndToResultError<T>(Log.ToUMMessage(msg, prefixLog), resultStatus, parameters);
        }

        public static Result ToUMNFResultError(string msg, ResultStatus resultStatus, string prefixLog = "")
        {
            return Log.ProcessAndToResultError(Log.ToUMMessage(msg, prefixLog), resultStatus);
        }

        public static string ToUMMessage(string msg, string prefixLog)
        {
            return Log.ToMNFMessage(Log.MessageForUser + msg, prefixLog, new
            {
            });
        }

        public static string ToMNFMessage<T>(string msg, string prefixLog, T parameters) where T : class
        {
            string str = Log.BuildParametersToString<T>(parameters);
            if (!string.IsNullOrEmpty(str))
                str = ": " + str;
            return msg + Log.MoreDetailLog + prefixLog + str;
        }

        public static string ToMNFMessage(string msg, string prefixLog)
        {
            return msg + Log.MoreDetailLog + prefixLog;
        }

        public static Result ProcessAndToResultError<T>(
          string msg,
          ResultStatus resultStatus,
          T parameters)
          where T : class
        {
            return ResultStatic.ToResultError(Log.ProcessError<T>(msg, parameters), resultStatus);
        }

        public static Result ProcessAndToResultError(string msg, ResultStatus resultStatus)
        {
            return ResultStatic.ToResultError(Log.ProcessError(msg, new
            {
            }), resultStatus);
        }

        public static string ProcessError<T>(string msg, T parameters) where T : class
        {
            return msg == null || msg.Length == 0 ? "" : Log.DoProcessError<T>(msg, parameters);
        }

        public static string DoProcessError<T>(string msg, T parameters) where T : class
        {
            Log.WriteErrorLog<T>(msg, parameters);
            return Log.GetMessageForUser(msg);
        }

        public static string GetMessageForUser(string msg)
        {
            if (!Log.IsMessageForUser(msg))
                return (string)null;
            if (msg.Contains(Log.MoreDetailLog))
                msg = msg.Substring(0, msg.IndexOf(Log.MoreDetailLog));
            return msg.Replace(Log.MessageForUser, "");
        }

        public static bool IsMessageForUser(string msg) => msg.Contains(Log.MessageForUser);

        public static string WriteErrorLog<T>(string LogContent, T parameters) where T : class
        {
            LogContent = Log.BuildLog<T>(LogContent, parameters);
            Log.Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\TinDuc Plugin\\LogError-" + DateTime.Now.ToString("dd-MM-yyyy") + ".txt", LogContent);
            return LogContent;
        }

        public static void WriteActivityLog(string LogContent)
        {
            Log.WriteActivityLog(LogContent, new { });
        }

        public static void WriteActivityLog<T>(string LogContent, T parameters) where T : class
        {
            LogContent = Log.BuildLog<T>(LogContent, parameters);
            Log.Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\TinDuc Plugin\\LogActivity-" + DateTime.Now.ToString("dd-MM-yyyy") + ".txt", LogContent);
        }

        private static string Add(string filePath, string logContent)
        {
            try
            {
                if (File.Exists(filePath))
                    logContent = Environment.NewLine + logContent;
                File.AppendAllText(filePath, logContent);
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }

        public static string BuildLog<T>(string message, T parameters) where T : class
        {
            string str = Log.BuildParametersToString<T>(parameters);
            if (str != "")
                str = ". {" + str + "}";
            return Log.BuildLog(message + str);
        }

        public static string BuildLog(string message)
        {
            return DateTime.Now.ToString("dd-MM-yyyy HH:mm:yy") + " [INFO] " + message;
        }

        public static string BuildParametersToString<T>(T parameters) where T : class
        {
            if ((object)parameters == null)
                return "";
            string str = "";
            foreach (PropertyInfo property in typeof(T).GetProperties())
                str = str + property.Name + ": " + property.GetValue((object)parameters, (object[])null)?.ToString() + "; ";
            return str.TrimEnd(' ', ';');
        }
    }
}
