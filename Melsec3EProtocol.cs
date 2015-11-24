using System;

namespace System.Net.Melsec
{
    public sealed class Melsec3EProtocol : MelsecEthProtocol
    {
        private const int ERROR_CODE_POSITION = 9;
        private const int MIN_RESPONSE_LENGTH = 10;
        private const int RETURN_VALUE_POSITION = 11;
        private const byte RETURN_PACKET_HEADER = 0xD0;
        private const byte DATA_LENGTH_POSITION = 7;

        internal Melsec3EProtocol(string ip, ushort port)
            : base(ip, port, ERROR_CODE_POSITION, MIN_RESPONSE_LENGTH, RETURN_VALUE_POSITION, RETURN_PACKET_HEADER, DATA_LENGTH_POSITION)
        {
            base.PacketHead = new byte[] { 0x50, 0x00 };
        }
    }
}