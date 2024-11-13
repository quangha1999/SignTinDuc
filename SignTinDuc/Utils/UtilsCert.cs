using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SignTinDuc
{
    public class UtilsCert
    {
        internal static string LoadCertificate(
          StoreName storeName,
          StoreLocation storeLocation,
          Hashtable filter,
          bool filterHasPrivateKey,
          out X509Certificate2 x509Certificate2)
        {
            x509Certificate2 = (X509Certificate2)null;
            X509Store x509Store = new X509Store(storeName, storeLocation);
            try
            {
                x509Store.Open(OpenFlags.OpenExistingOnly);
                X509Certificate2Collection certificates = x509Store.Certificates;
                if (filter != null && filter.Count > 0)
                {
                    IDictionaryEnumerator enumerator = filter.GetEnumerator();
                    if (enumerator == null)
                        return "Hashtable enumerator is null";
                    while (enumerator.MoveNext())
                    {
                        if (!(enumerator.Key is X509FindType key))
                            return "findType is invalid.";
                        certificates = certificates.Find(key, enumerator.Value, false);
                    }
                }
                if (filterHasPrivateKey)
                {
                    for (int index = certificates.Count - 1; index >= 0; --index)
                    {
                        if (!certificates[index].HasPrivateKey)
                            certificates.RemoveAt(index);
                    }
                }
                if (certificates.Count == 0)
                    return "Certificates not found";
                if (certificates.Count == 1)
                {
                    X509Certificate2Enumerator enumerator = certificates.GetEnumerator();
                    if (enumerator == null)
                        return "X509Certificate2Collection enumerator is null";
                    if (!enumerator.MoveNext())
                        return (string)null;
                    x509Certificate2 = enumerator.Current;
                    return x509Certificate2 == null ? "certificate2Enum.Current is null" : string.Empty;
                }
                if (certificates.Count > 1)
                {
                    X509Certificate2Collection certificate2Collection;
                    try
                    {
                        certificate2Collection = X509Certificate2UI.SelectFromCollection(certificates, "Certificate Select", "Select a certificate from the following list", X509SelectionFlag.SingleSelection);
                    }
                    catch (Exception ex)
                    {
                        return Log.ToMNFMessage(ex.ToString(), "X509Certificate2UI.SelectFromCollection");
                    }
                    if (certificate2Collection == null || certificate2Collection.Count == 0)
                        return "selectColl is empty";
                    if (certificate2Collection.Count != 1)
                        return "Select more than 1 certificate";
                    x509Certificate2 = certificate2Collection[0];
                }
            }
            catch (CryptographicException ex)
            {
                return ex.ToString();
            }
            finally
            {
                x509Store.Close();
            }
            return string.Empty;
        }

        public static string LoadCertBySerialnumber(
          string serialnumber,
          out X509Certificate2 x509Certificate2)
        {
            x509Certificate2 = (X509Certificate2)null;
            try
            {
                Hashtable filter = new Hashtable()
        {
          {
            (object) X509FindType.FindBySerialNumber,
            (object) serialnumber
          }
        };
                string msg1 = UtilsCert.LoadCertificate(StoreName.My, StoreLocation.CurrentUser, filter, true, out x509Certificate2);
                if (msg1.Length > 0)
                    Log.ToMNFMessage(msg1, "LoadCertificate", new
                    {
                        storeName = StoreName.My,
                        storeLocation = StoreLocation.CurrentUser
                    });
                if (x509Certificate2 == null)
                {
                    string msg2 = UtilsCert.LoadCertificate(StoreName.My, StoreLocation.LocalMachine, filter, true, out x509Certificate2);
                    if (msg2.Length > 0)
                        return Log.ToMNFMessage(msg2, "LoadCertificate", new
                        {
                            storeName = StoreName.My,
                            storeLocation = StoreLocation.LocalMachine
                        });
                    if (x509Certificate2 == null)
                        return "x509Cert2 is null";
                }
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }

        public static string CertificateListAll(out List<Certificate> certList)
        {
            certList = new List<Certificate>();
            try
            {
                List<Certificate> certList1;
                string str1 = UtilsCert.CertificateList(StoreLocation.CurrentUser, out certList1);
                if (str1.Length > 0)
                    return str1;
                certList.AddRange((IEnumerable<Certificate>)certList1);
                List<Certificate> certList2;
                string str2 = UtilsCert.CertificateList(StoreLocation.LocalMachine, out certList2);
                if (str2.Length > 0)
                    return str2;
                certList.AddRange((IEnumerable<Certificate>)certList2);
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            return "";
        }

        public static string CertificateList(
          StoreLocation storeLocation,
          out List<Certificate> certList)
        {
            certList = new List<Certificate>();
            X509Store x509Store = new X509Store(storeLocation);
            try
            {
                x509Store.Open(OpenFlags.ReadOnly);
                X509Certificate2Enumerator enumerator = x509Store.Certificates.GetEnumerator();
                while (enumerator.MoveNext())
                {
                    X509Certificate2 current = enumerator.Current;
                    string subject = current.Subject;
                    string issuer = current.Issuer;
                    string serialNumberString = current.GetSerialNumberString();
                    DateTime dateTime = current.NotBefore;
                    string TimeValidFrom = dateTime.ToString("MM/dd/yyyy HH:mm:ss");
                    dateTime = current.NotAfter;
                    string TimeValidTo = dateTime.ToString("MM/dd/yyyy HH:mm:ss");
                    Certificate certificate = new Certificate(subject, issuer, serialNumberString, TimeValidFrom, TimeValidTo);
                    certList.Add(certificate);
                }
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
            finally
            {
                x509Store.Close();
            }
            return "";
        }

        public static string CheckInsertUsbToken(out bool CheckCertificate)
        {
            CheckCertificate = false;
            try
            {
                X509Store x509Store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                x509Store.Open(OpenFlags.ReadOnly);
                X509Certificate2Enumerator enumerator = x509Store.Certificates.GetEnumerator();
                while (enumerator.MoveNext())
                {
                    X509Certificate2 current = enumerator.Current;
                    try
                    {
                        if (current.HasPrivateKey)
                        {
                            if (current.PrivateKey is ICspAsymmetricAlgorithm)
                            {
                                CheckCertificate = true;
                                return "";
                            }
                        }
                    }
                    catch
                    {
                    }
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
