using System;

namespace System.Net.Melsec
{
    public sealed class MelsecEthClient : MelsecClient
    {
        public MelsecEthClient(MelsecEthProtocol protocol, int receiveTimeout, int sendTimeout)
            : base(protocol, receiveTimeout, sendTimeout)
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