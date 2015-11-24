using System;

namespace System.Net.Melsec
{
    public sealed class Melsec4EProtocol : MelsecEthProtocol
    {
        private const int ERROR_CODE_POSITION = 13;
        private const int MIN_RESPONSE_LENGTH = 14;
        private const int RETURN_VALUE_POSITION = 15;
        private const byte RETURN_PACKET_HEADER = 0xD4;
        private const byte DATA_LENGTH_POSITION = 11;

        internal Melsec4EProtocol(string ip, ushort port)
            : base(ip, port, ERROR_CODE_POSITION, MIN_RESPONSE_LENGTH, RETURN_VALUE_POSITION, RETURN_PACKET_HEADER, DATA_LENGTH_POSITION)
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

        public override void ErrLedOff()
        {
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,destinationCpu,0x03,0x00,0x06,0x00,0x10,0x00,
                0x17,0x16,
                0x00,0x00};
            SendBuffer(sendbuffer);
        }

        public override void Run(bool forced, ClearMode mode)
        {
            byte frcd = (forced) ? frcd = 0x03 : frcd = 0x01;
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,destinationCpu,0x03,0x00,0x0A,0x00,0x10,0x00,
                0x01,0x10,
                0x00,0x00,
                frcd,0x00,
                (byte)mode, 0x00};
            SendBuffer(sendbuffer);
        }

        public override void Pause(bool forced)
        {
            byte frcd = (forced) ? frcd = 0x03 : frcd = 0x01;
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,destinationCpu,0x03,0x00,0x08,0x00,0x10,0x00,
                0x03,0x10,
                0x00,0x00,
                frcd,0x00};
            SendBuffer(sendbuffer);
        }

        public override void Stop()
        {
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,destinationCpu,0x03,0x00,0x08,0x00,0x10,0x00,
                0x02,0x10,
                0x00,0x00,
                0x01,0x00};
            SendBuffer(sendbuffer);
        }

        public override void Reset()
        {
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,destinationCpu,0x03,0x00,0x08,0x00,0x10,0x00,
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
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,destinationCpu,0x03,0x00,0x08,0x00,0x10,0x00,
                0x05,0x10,
                0x00,0x00,
                0x01,0x00};
            SendBuffer(sendbuffer);
        }
    }
}