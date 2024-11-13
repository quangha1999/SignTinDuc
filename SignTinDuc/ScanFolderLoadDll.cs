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
        public static List<string> FindPKCS11DLLs()
        {
            List<string> dllPaths = new List<string>();

            // 2. Tìm kiếm trong thư mục cài đặt chương trình
            dllPaths.AddRange(FindDLLsInProgramFiles());

            // 3. Tìm kiếm trong thư mục hệ thống (System32 và SysWOW64)
            dllPaths.AddRange(FindDLLsInSystemFolders());

            // Loại bỏ các đường dẫn trùng lặp
            dllPaths = dllPaths.Distinct().ToList();

            return dllPaths;
        }
        public static List<string> FindDLLsInProgramFiles()
        {
            List<string> dllPaths = new List<string>();
            string[] directories = { @"C:\Program Files\", @"C:\Program Files (x86)\" };
            string[] keywords = {
        "bkavcaetoken", "bkavcsp", "BkavCA", "beidcsp", "BkavCAv2S", "bkavcaetoken_p11",
        "viettel-ca_v2", "viettel-ca_v3", "viettel-ca_v4", "viettel-ca_v5", "beidpkcs11D",
        "nca_v4", "nca_v4_csp", "nca_v6", "viettel-ca", "vnptca_p11_v6", "vnptca_p11_v6_s",
        "vnptca_p11_v7", "vnptca_p11_v8", "vnptca_p11_v9", "vnptca_p11_v10", "vnpt-ca_csp11",
        "vnpt-ca_v34", "vnpt-ca_cl_v1", "wdsafe3", "CA2_v34", "CA2_csp11", "ca2_ace_csp11",
        "CA2CSP11_v2", "st3csp11", "viettel-ca_v1", "viettel-ca_v2", "viettel-ca_v3",
        "viettel-ca_v4", "viettel-ca_v5", "viettel-ca_v6", "viettel-ca_s", "viettel-ca_v2_csp",
        "viettel-ca_v2_csp.EN", "viettel-ca_v2_csp.VN", "viettel-ca_v2_s", "fptca_v3",
        "fptca_v3_s", "fpt-ca", "fpt-ca-stx", "fpt_ca", "CKCA", "safe-ca", "safe-ca_v2",
        "Vina-CA", "Vina-CAv3", "Vina-CA_s", "Vina-CAv4", "Vina-CAv5", "NEWTEL-CA", "vdctdcsp11",
        "ShuttleCsp11_3003", "ngp11v211", "gclib", "psapkcs", "ostc1_csp11", "etpkcs11",
        "U1000AUTO", "eToken", "ostt1_csp11", "ostt2_csp11", "ostt3_csp11", "ostc2_csp11",
        "nca_eps2k2a", "nca_eps2k3a"
    };

            foreach (string directory in directories)
            {
                if (Directory.Exists(directory))
                {
                    try
                    {
                        var dllFiles = Directory.GetFiles(directory, "*.dll", SearchOption.AllDirectories)
                            .Where(path => keywords.Any(keyword => path.ToLower().Contains(keyword)));

                        dllPaths.AddRange(dllFiles);
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        Console.WriteLine($"Access denied to directory: {directory}. Skipping.");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error accessing directory: {directory}. Error: {ex.Message}");
                    }
                }
            }

            return dllPaths;
        }

        public static List<string> FindDLLsInSystemFolders()
        {
            List<string> dllPaths = new List<string>();
            string[] systemFolders = { @"C:\Windows\System32\"};
            string[] knownDllNames = {
              "bkavcaetoken", "bkavcsp", "BkavCA", "beidcsp", "BkavCAv2S", "bkavcaetoken_p11",
        "viettel-ca_v2", "viettel-ca_v3", "viettel-ca_v4", "viettel-ca_v5", "beidpkcs11D",
        "nca_v4", "nca_v4_csp", "nca_v6", "viettel-ca", "vnptca_p11_v6", "vnptca_p11_v6_s",
        "vnptca_p11_v7", "vnptca_p11_v8", "vnptca_p11_v9", "vnptca_p11_v10", "vnpt-ca_csp11",
        "vnpt-ca_v34", "vnpt-ca_cl_v1", "wdsafe3", "CA2_v34", "CA2_csp11", "ca2_ace_csp11",
        "CA2CSP11_v2", "st3csp11", "viettel-ca_v1", "viettel-ca_v2", "viettel-ca_v3",
        "viettel-ca_v4", "viettel-ca_v5", "viettel-ca_v6", "viettel-ca_s", "viettel-ca_v2_csp",
        "viettel-ca_v2_csp.EN", "viettel-ca_v2_csp.VN", "viettel-ca_v2_s", "fptca_v3",
        "fptca_v3_s", "fpt-ca", "fpt-ca-stx", "fpt_ca", "CKCA", "safe-ca", "safe-ca_v2",
        "Vina-CA", "Vina-CAv3", "Vina-CA_s", "Vina-CAv4", "Vina-CAv5", "NEWTEL-CA", "vdctdcsp11",
        "ShuttleCsp11_3003", "ngp11v211", "gclib", "psapkcs", "ostc1_csp11", "etpkcs11",
        "U1000AUTO", "eToken", "ostt1_csp11", "ostt2_csp11", "ostt3_csp11", "ostc2_csp11",
        "nca_eps2k2a", "nca_eps2k3a"};

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
