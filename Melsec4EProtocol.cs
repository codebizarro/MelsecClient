using System;

namespace Melsec
{
    public sealed class Melsec4EProtocol : MelsecEthProtocol
    {
        private const int ERROR_CODE_POSITION = 13;
        private const int MIN_RESPONSE_LENGTH = 14;
        private const int RETURN_VALUE_POSITION = 15;
        private const byte RETURN_PACKET_HEADER = 0xD4;

        public Melsec4EProtocol(string ip, ushort port)
            : base(ip, port, ERROR_CODE_POSITION, MIN_RESPONSE_LENGTH, RETURN_VALUE_POSITION, RETURN_PACKET_HEADER)
        {
            Random rnd = new Random();
            serialNo = (ushort)rnd.Next(ushort.MinValue, ushort.MaxValue);
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

        public override float ReadReal(ushort point, MelsecDeviceType DeviceType)
        {
            byte[] addr = GetPointBytes(point);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                0x00,0xFF,0xFF,0x03,0x00,0x0C,0x00,0x10,0x00,
				0x01,0x04,0x00,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				0x02,0x00};
            byte[] recvbuffer = SendBuffer(sendbuffer);
            float ret = BitConverter.ToSingle(recvbuffer, ReturnValuePosition);
            return ret;
        }

        public override float[] ReadReal(ushort point, MelsecDeviceType DeviceType, byte count)
        {
            byte[] addr = GetPointBytes(point);
            byte[] cnt = GetPointCount((ushort)(count * 2));
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                0x00,0xFF,0xFF,0x03,0x00,0x0C,0x00,0x10,0x00,
				0x01,0x04,0x00,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				cnt[0],cnt[1]};
            byte[] recvbuffer = SendBuffer(sendbuffer);
            int dataLen = recvbuffer.Length - ReturnValuePosition;
            int retLen = dataLen / 4;
            int blockLen = retLen * 4;
            float[] ret = new float[retLen];
            Buffer.BlockCopy(recvbuffer, ReturnValuePosition, ret, 0, blockLen);
            return ret;
        }

        public override void WriteReal(ushort point, float val, MelsecDeviceType DeviceType)
        {
            byte[] addr = GetPointBytes(point);
            byte[] rVal = BitConverter.GetBytes(val);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                0x00,0xFF,0xFF,0x03,0x00,0x10,0x00,0x10,0x00,
				0x01,0x14,0x00,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				0x02,0x00,
				rVal[0], rVal[1], rVal[2], rVal[3]};
            SendBuffer(sendbuffer);
        }

        public override uint ReadDword(ushort point, MelsecDeviceType DeviceType)
        {
            byte[] addr = GetPointBytes(point);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                0x00,0xFF,0xFF,0x03,0x00,0x0C,0x00,0x10,0x00,
				0x01,0x04,0x00,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				0x02,0x00};
            byte[] recvbuffer = SendBuffer(sendbuffer);
            uint ret = BitConverter.ToUInt32(recvbuffer, ReturnValuePosition);
            return ret;
        }

        public override uint[] ReadDword(ushort point, MelsecDeviceType DeviceType, byte count)
        {
            byte[] addr = GetPointBytes(point);
            byte[] cnt = GetPointCount((ushort)(count * 2));
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                0x00,0xFF,0xFF,0x03,0x00,0x0C,0x00,0x10,0x00,
				0x01,0x04,0x00,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				cnt[0],cnt[1]};
            byte[] recvbuffer = SendBuffer(sendbuffer);
            int dataLen = recvbuffer.Length - ReturnValuePosition;
            int retLen = dataLen / 4;
            int blockLen = retLen * 4;
            uint[] ret = new uint[retLen];
            Buffer.BlockCopy(recvbuffer, ReturnValuePosition, ret, 0, blockLen);
            return ret;
        }

        public override void WriteDword(ushort point, uint val, MelsecDeviceType DeviceType)
        {
            byte[] addr = GetPointBytes(point);
            byte[] dwVal = BitConverter.GetBytes(val);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                0x00,0xFF,0xFF,0x03,0x00,0x10,0x00,0x10,0x00,
				0x01,0x14,0x00,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				0x02,0x00,
				dwVal[0], dwVal[1], dwVal[2], dwVal[3]};
            SendBuffer(sendbuffer);
        }

        public override ushort ReadWord(ushort point, MelsecDeviceType DeviceType)
        {
            byte[] addr = GetPointBytes(point);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                0x00,0xFF,0xFF,0x03,0x00,0x0C,0x00,0x10,0x00,
				0x01,0x04,0x00,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				0x01,0x00};
            byte[] recvbuffer = SendBuffer(sendbuffer);
            ushort ret = BitConverter.ToUInt16(recvbuffer, ReturnValuePosition);
            return ret;
        }

        public override ushort[] ReadWord(ushort point, MelsecDeviceType DeviceType, byte count)
        {
            byte[] addr = GetPointBytes(point);
            byte[] cnt = GetPointCount(count);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                0x00,0xFF,0xFF,0x03,0x00,0x0C,0x00,0x10,0x00,
				0x01,0x04,0x00,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				cnt[0],cnt[1]};
            byte[] recvbuffer = SendBuffer(sendbuffer);
            int dataLen = recvbuffer.Length - ReturnValuePosition;
            int retLen = dataLen / 2;
            int blockLen = retLen * 2;
            ushort[] ret = new ushort[retLen];
            Buffer.BlockCopy(recvbuffer, ReturnValuePosition, ret, 0, blockLen);
            return ret;
        }

        public override void WriteWord(ushort point, ushort val, MelsecDeviceType DeviceType)
        {
            byte[] addr = GetPointBytes(point);
            byte[] wVal = BitConverter.GetBytes(val);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                0x00,0xFF,0xFF,0x03,0x00,0x0E,0x00,0x10,0x00,
				0x01,0x14,0x00,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				0x01,0x00,
				wVal[0], wVal[1]};
            SendBuffer(sendbuffer);
        }

        public override bool ReadByte(ushort point, MelsecDeviceType DeviceType)
        {
            byte[] addr = GetPointBytes(point);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                0x00,0xFF,0xFF,0x03,0x00,0x0C,0x00,0x10,0x00,
				0x01,0x04,0x01,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				0x01,0x00};
            byte[] recvbuffer = SendBuffer(sendbuffer);
            bool ret = BitConverter.ToBoolean(recvbuffer, ReturnValuePosition);
            return ret;
        }

        public override bool[] ReadByte(ushort point, MelsecDeviceType DeviceType, byte count)
        {
            byte[] addr = GetPointBytes(point);
            byte[] cnt = GetPointCount(count);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                0x00,0xFF,0xFF,0x03,0x00,0x0C,0x00,0x10,0x00,
				0x01,0x04,0x01,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				cnt[0],cnt[1]};
            byte[] recvbuffer = SendBuffer(sendbuffer);
            int dataLen = recvbuffer.Length - ReturnValuePosition;
            int retLen = dataLen * 2;
            bool[] ret = new bool[retLen];
            for (int i = 0, j = 0; i < dataLen; ++i, j += 2)
            {
                byte recvByte = recvbuffer[ReturnValuePosition + i];
                byte[] retB = new byte[1];
                retB[0] = (byte)(recvByte >> 4);
                ret[j] = BitConverter.ToBoolean(retB, 0);
                retB[0] = (byte)(recvByte & 1);
                ret[j + 1] = BitConverter.ToBoolean(retB, 0);
            }

            return ret;
        }

        public override void WriteByte(ushort point, bool state, MelsecDeviceType DeviceType)
        {
            byte[] addr = GetPointBytes(point);
            byte On;
            if (state) On = 0x10;
            else On = 0x00;
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                0x00,0xFF,0xFF,0x03,0x00,0x0D,0x00,0x10,0x00,
				0x01,0x14,0x01,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				0x01,0x00,
				On};
            SendBuffer(sendbuffer);
        }

        public override void ErrLedOff()
        {
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                0x00,0xFF,0xFF,0x03,0x00,0x06,0x00,0x10,0x00,
				0x17,0x16,
				0x00,0x00};
            SendBuffer(sendbuffer);
        }
    }
}