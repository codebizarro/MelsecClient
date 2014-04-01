using System;

namespace System.Net.Melsec
{
    public sealed class MelsecComClient : MelsecClient
    {
        public MelsecComClient(ProtocolType protocoltype, string ip, ushort port, int receiveTimeout, int sendTimeout)
            : base(protocoltype, ip, port, receiveTimeout, sendTimeout)
        {
        }

        public MelsecComProtocol Protocol
        {
            get
            {
                return (MelsecComProtocol)melsecProtocol;
            }
        }
    }
}