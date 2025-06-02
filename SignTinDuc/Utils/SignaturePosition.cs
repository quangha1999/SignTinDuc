using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignTinDuc.Utils
{
    public class SignaturePosition
    {
        public float x { get; set; }
        public float y { get; set; }
        public float width { get; set; }
        public float height { get; set; }
        public int page { get; set; }
        public string text { get; set; }
        public string fontName { get; set; }
        public int fontStyle { get; set; } // chưa dùng
        public float fontSize { get; set; }
        public string fontColor { get; set; } // dạng "000", "F00"...
    }
}
