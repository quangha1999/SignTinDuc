using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignTinDuc
{
    public class Result
    {
        public Result() { }
        public Result(int status, object obj, bool isOk, bool isError,string mess)
        {
            this.Status = status;
            this.Object = obj;
            this.isOk = isOk;
            this.isError = isError;
            this.messageId= mess;
        }

        public int Status { get; set; }

        public object Object { get; set; }

        public bool isOk { get; set; }

        public bool isError { get; set; }
        public string messageId { get; set; }
    }
}
