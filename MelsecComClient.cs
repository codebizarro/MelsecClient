using System;

namespace Melsec
{
    public sealed class MelsecComClient : MelsecClient
    {
        public MelsecComClient(MelsecComProtocol protocol, int receiveTimeout, int sendTimeout)
            : base(protocol, receiveTimeout, sendTimeout)
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