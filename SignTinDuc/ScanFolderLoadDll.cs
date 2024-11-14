using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignTinDuc
{
    public class ScanFolderLoadDll
    {
        public static List<string> FindPKCS11DLLs(string data,string[] arrData)
        {
            string listDLL = arrData[1];
            List<string> dllPaths = new List<string>();
            // Tìm kiếm trong thư mục hệ thống
            dllPaths.AddRange(FindDLLsInSystemFolders(listDLL));
            // Loại bỏ các đường dẫn trùng lặp
            dllPaths = dllPaths.Distinct().ToList();
            return dllPaths;
        }
        public static List<string> FindDLLsInSystemFolders(string listDLL)
        {
            List<string> dllPaths = new List<string>();
            string[] systemFolders = { @"C:\Windows\System32\", @"C:\Windows\SysWOW64\", @"C:\Program Files\", @"C:\Program Files (x86)\" };
            string[] knownDllNames = listDLL.Split(',');
            foreach (string systemFolder in systemFolders)
            {
                if (Directory.Exists(systemFolder))
                {
                    foreach (var dllName in knownDllNames)
                    {
                        var dllPath = Path.Combine(systemFolder, dllName+".dll");
                        if (File.Exists(dllPath))
                        {
                            dllPaths.Add(dllPath);
                        }
                    }
                }
            }
            return dllPaths;
        }
    }
}
