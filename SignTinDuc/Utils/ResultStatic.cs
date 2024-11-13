using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignTinDuc
{
    public static class ResultStatic
    {
        public static Result ResultOk(object obj) => new Result(0, obj, true, false);

        public static Result ToResultError(string msgError, ResultStatus resultStatus)
        {
            return new Result((int)resultStatus, (object)msgError, false, true);
        }
    }
}
