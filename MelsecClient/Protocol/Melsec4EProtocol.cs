using System;

namespace System.Net.Melsec
{
    public sealed class Melsec4EProtocol : MelsecEthProtocol
    {
        internal Melsec4EProtocol(string ip, ushort port)
            : base(ip, port,
                  errorCodePosition: 13,
                  minResponseLength: 14,
                  returnValuePosition: 15,
                  returnPacketHeader: 0xD4,
                  dataLengthPosition: 11)
        {
            Random rnd = new Random();
            serialNo = (ushort)rnd.Next(ushort.MinValue, ushort.MaxValue);
            base.PacketHead = new byte[] { 0x54, 0x00, SerialNo[0], SerialNo[1], 0x00, 0x00 };
        }

        private readonly ushort serialNo;

        private byte[] SerialNo
        {
            get
            {
                return BitConverter.GetBytes(serialNo);
            }
        }

        protected override byte[] SendBuffer(byte[] buffer)
        {
            byte[] ret = base.SendBuffer(buffer);
            if (ret[2] != SerialNo[0] || ret[3] != SerialNo[1])
                throw new Exception("Different returned serialNo with sended");
            else return ret;
        }
    }
}