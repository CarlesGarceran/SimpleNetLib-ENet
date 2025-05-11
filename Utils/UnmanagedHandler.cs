using SimpleNetLib_ENet.Wrapper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SimpleNetLib_ENet.Utils
{
    internal static class UnmanagedHandler
    {
        public static byte[] GetPacketBuffer(Packet e)
        {
            int packetSize = e.Length;
            byte[] data = new byte[packetSize];

            e.CopyTo(data);

            return data;
        }
    }
}
