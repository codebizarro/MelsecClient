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
    }
}