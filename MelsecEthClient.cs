using System;

namespace System.Net.Melsec
{
    public sealed class MelsecEthClient : MelsecClient
    {
        public MelsecEthClient(ProtocolType protocoltype, string ip, ushort port, int receiveTimeout, int sendTimeout)
            : base(protocoltype, ip, port, receiveTimeout, sendTimeout)
        {
        }

        public MelsecEthProtocol Protocol
        {
            get
            {
                return (MelsecEthProtocol)melsecProtocol;
            }
        }

        public override string ToString()
        {
            return Protocol.ToString();
        }

        public bool ErrLed()
        {
            ushort[] buff = Protocol.ReadBuffer<ushort>(0xC8, 1);
            return ((buff[0] & (1 << 4)) != 0);
        }
    }
}