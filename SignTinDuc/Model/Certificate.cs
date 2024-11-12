using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignTinDuc.Model
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
    }
}
