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

        public override void ErrLedOff()
        {
            byte[] sendbuffer = new byte[] {0x50,0x00,NetNo,PcNo,destinationCpu,0x03,0x00,0x06,0x00,0x10,0x00,
                0x17,0x16,
                0x00,0x00};
            SendBuffer(sendbuffer);
        }

        public override void Run(bool forced, ClearMode mode)
        {
            byte frcd = (forced) ? frcd = 0x03 : frcd = 0x01;
            byte[] sendbuffer = new byte[] {0x50,0x00,NetNo,PcNo,destinationCpu,0x03,0x00,0x0A,0x00,0x10,0x00,
                0x01,0x10,
                0x00,0x00,
                frcd,0x00,
                (byte)mode, 0x00};
            SendBuffer(sendbuffer);
        }

        public override void Pause(bool forced)
        {
            byte frcd = (forced) ? frcd = 0x03 : frcd = 0x01;
            byte[] sendbuffer = new byte[] {0x50,0x00,NetNo,PcNo,destinationCpu,0x03,0x00,0x08,0x00,0x10,0x00,
                0x03,0x10,
                0x00,0x00,
                frcd,0x00};
            SendBuffer(sendbuffer);
        }

        public override void Stop()
        {
            byte[] sendbuffer = new byte[] {0x50,0x00,NetNo,PcNo,destinationCpu,0x03,0x00,0x08,0x00,0x10,0x00,
                0x02,0x10,
                0x00,0x00,
                0x01,0x00};
            SendBuffer(sendbuffer);
        }

        public override void Reset()
        {
            byte[] sendbuffer = new byte[] {0x50,0x00,NetNo,PcNo,destinationCpu,0x03,0x00,0x08,0x00,0x10,0x00,
                0x06,0x10,
                0x00,0x00,
                0x01,0x00};
            try
            {
                SendBuffer(sendbuffer);
            }
            catch { }
        }

        public override void LatchClear()
        {
            byte[] sendbuffer = new byte[] {0x50,0x00,NetNo,PcNo,destinationCpu,0x03,0x00,0x08,0x00,0x10,0x00,
                0x05,0x10,
                0x00,0x00,
                0x01,0x00};
            SendBuffer(sendbuffer);
        }
    }
}