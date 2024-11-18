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
        public static List<string> FindPKCS11DLLs(string[] arrData)
        {
           
            List<string> dllPaths = new List<string>();
            // Tìm kiếm trong thư mục hệ thống
            foreach (string dll in arrData) {
                dllPaths.AddRange(FindDLLsInSystemFolders(dll));
            }
            // Loại bỏ các đường dẫn trùng lặp
            var uniqueDllPaths = dllPaths
            .GroupBy(path => System.IO.Path.GetFileName(path))
            .Select(group => group.First())
            .ToList();
            return uniqueDllPaths;
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
