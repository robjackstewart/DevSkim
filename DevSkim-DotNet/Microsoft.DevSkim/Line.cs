using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.DevSkim
{
    public class Line
    {
        public readonly string Content;
        public Line(string content)
            => Content = content;
    }
}
