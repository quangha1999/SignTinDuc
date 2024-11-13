using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignTinDuc
{
    public class Device
    {
        public string TokenName { get; set; }

        public string SerialName { get; set; }

        public string MemoryAll { get; set; }

        public string MemoryEmpty { get; set; }

        public string PinMax { get; set; }
        public string PinMin { get; set; }
        public string Version { get; set; }
        public string FirmWare { get; set; }
        public string Icon { get; set; }
        public Device() { }
        public Device(
             string tokenName,
             string serialName,
             string memoryAll,
             string memoryEmpty,
             string pinMax,
             string pinMin,
             string version,
             string firmWare,
             string icon
          )
        {
            this.TokenName = tokenName;
            this.SerialName = serialName;
            this.MemoryAll = memoryAll;
            this.MemoryEmpty = memoryEmpty;
            this.PinMax = pinMax;
            this.PinMin = pinMin;
            this.Version = version;
            this.FirmWare = firmWare;
            this.Icon = icon;
        }
    }
}
