using Microsoft.VisualBasic.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Resources.ResXFileRef;

namespace SignTinDuc
{
    public class Certificate
    {
        public string SubjectDN { get; set; }

        public string IssuerDN { get; set; }

        public string SerialNumber { get; set; }

        public string TimeValidFrom { get; set; }

        public string TimeValidTo { get; set; }
        public Certificate()
        {
        }

        public Certificate(
          string SubjectDN,
          string IssuerDN,
          string SerialNumber,
          string TimeValidFrom,
          string TimeValidTo)
        {
            this.SubjectDN = SubjectDN;
            this.IssuerDN = IssuerDN;
            this.SerialNumber = SerialNumber;
            this.TimeValidFrom = TimeValidFrom;
            this.TimeValidTo = TimeValidTo;
        }
        public static Result GetListCert()
        {
            Log.WriteActivityLog("Get list certs");
            List<Certificate> certList;
            string msg = UtilsCert.CertificateListAll(out certList);
            return msg.Length > 0 ? Log.ToUMNFResultError(msg, ResultStatus.ERROR_FOUND_CERT, "CertUtils.CertificateList", new
            {
                function = 4
            }) : ResultStatic.ResultOk((object)Convert.ToBase64String(Encoding.UTF8.GetBytes(Convertor.Serialize((object)certList))));
        }
    }
}
