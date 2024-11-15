using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignTinDuc
{
    public enum ResultStatus
    {
        ERROR_FOUND_NODE_RESULT_XML = -9, // 0xFFFFFFF7
        ERROR_ASSCES_CONNECT = -8, // 0xFFFFFFF8
        ERROR_IN_PROGRESS_SIGN = -7, // 0xFFFFFFF9
        ERROR_CONVERT_DATA = -6, // 0xFFFFFFFA
        ERROR_FOUND_CERT = -5, // 0xFFFFFFFB
        ERROR_CERTIFICATE_LIST = -4, // 0xFFFFFFFC
        ERROR_INPUT = -1, // 0xFFFFFFFF
        OK = 0,
        ERROR = 1,
        
    }
}
