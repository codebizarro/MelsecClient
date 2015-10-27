using System;

namespace System.Net.Melsec
{
    public sealed class Melsec4EProtocol : MelsecEthProtocol
    {
        private const int ERROR_CODE_POSITION = 13;
        private const int MIN_RESPONSE_LENGTH = 14;
        private const int RETURN_VALUE_POSITION = 15;
        private const byte RETURN_PACKET_HEADER = 0xD4;

        internal Melsec4EProtocol(string ip, ushort port)
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
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x0C,0x00,0x10,0x00,
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
            byte[] cnt = GetPointCount(count * 2);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x0C,0x00,0x10,0x00,
				0x01,0x04,0x00,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				cnt[0],cnt[1]};
            byte[] recvbuffer = SendBuffer(sendbuffer);
            int dataLen = recvbuffer.Length - ReturnValuePosition;
            int retLen = dataLen / 4;
            float[] ret = new float[retLen];
            Buffer.BlockCopy(recvbuffer, ReturnValuePosition, ret, 0, dataLen);
            return ret;
        }

        public override float[] ReadReal(ushort[] point, MelsecDeviceType DeviceType)
        {
            if (point.Length == 0)
                throw new Exception(Globals.NO_DATA_READ);
            ushort count = (ushort)point.Length;
            byte[] sendbuffer = new byte[21 + count * 4];
            byte[] len = GetRequestDataLength(sendbuffer.Length - ERROR_CODE_POSITION);
            byte[] buff1 = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,len[0],len[1],0x10,0x00,
				0x03,0x04,0x00,0x00,0x00,(byte)count};
            Array.Copy(buff1, sendbuffer, buff1.Length);
            for (int i = 0; i < count; ++i)
            {
                byte[] addr = GetPointBytes(point[i]);
                byte[] buff2 = new byte[] { addr[0], addr[1], addr[2], (byte)DeviceType };
                Array.Copy(buff2, 0, sendbuffer, buff1.Length + i * buff2.Length, buff2.Length);
            }
            byte[] recvbuffer = SendBuffer(sendbuffer);
            int dataLen = recvbuffer.Length - ReturnValuePosition;
            int retLen = dataLen / 4;
            float[] ret = new float[retLen];
            Buffer.BlockCopy(recvbuffer, ReturnValuePosition, ret, 0, dataLen);
            return ret;
        }

        public override void WriteReal(ushort point, float val, MelsecDeviceType DeviceType)
        {
            byte[] addr = GetPointBytes(point);
            byte[] rVal = BitConverter.GetBytes(val);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x10,0x00,0x10,0x00,
				0x01,0x14,0x00,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				0x02,0x00,
				rVal[0], rVal[1], rVal[2], rVal[3]};
            SendBuffer(sendbuffer);
        }

        public override void WriteReal(ushort point, float[] val, MelsecDeviceType DeviceType)
        {
            if (val.Length == 0)
                throw new Exception(Globals.NO_DATA_WRITE);
            byte[] addr = GetPointBytes(point);
            ushort count = (ushort)val.Length;
            byte[] cnt = GetPointCount(count * 2);
            byte[] sendbuffer = new byte[25 + count * 4];
            byte[] len = GetRequestDataLength(sendbuffer.Length - ERROR_CODE_POSITION);
            byte[] buff1 = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,len[0],len[1],0x10,0x00,
                0x01,0x14,0x00,0x00,addr[0],addr[1],addr[2],(byte)DeviceType,cnt[0],cnt[1]};
            Array.Copy(buff1, sendbuffer, buff1.Length);
            for (int i = 0; i < count; ++i)
            {
                byte[] rval = BitConverter.GetBytes(val[i]);
                byte[] buff2 = new byte[] { rval[0], rval[1], rval[2], rval[3] };
                Array.Copy(buff2, 0, sendbuffer, buff1.Length + i * buff2.Length, buff2.Length);
            }
            SendBuffer(sendbuffer);
        }

        public override void WriteReal(ushort[] point, float[] val, MelsecDeviceType DeviceType)
        {
            if (point.Length != val.Length)
                throw new Exception(Globals.SIZE_MISMATCH);
            if (val.Length == 0)
                throw new Exception(Globals.NO_DATA_WRITE);
            ushort count = (ushort)point.Length;
            byte[] sendbuffer = new byte[21 + count * 8];
            byte[] len = GetRequestDataLength(sendbuffer.Length - ERROR_CODE_POSITION);
            byte[] buff1 = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,len[0],len[1],0x10,0x00,
				0x02,0x14,0x00,0x00,0x00,(byte)count};
            Array.Copy(buff1, sendbuffer, buff1.Length);
            for (int i = 0; i < count; ++i)
            {
                byte[] addr = GetPointBytes(point[i]);
                byte[] rval = BitConverter.GetBytes(val[i]);
                byte[] buff2 = new byte[] { addr[0], addr[1], addr[2], (byte)DeviceType,
                                            rval[0], rval[1], rval[2], rval[3]};
                Array.Copy(buff2, 0, sendbuffer, buff1.Length + i * buff2.Length, buff2.Length);
            }
            SendBuffer(sendbuffer);
        }

        public override uint ReadDword(ushort point, MelsecDeviceType DeviceType)
        {
            byte[] addr = GetPointBytes(point);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x0C,0x00,0x10,0x00,
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
            byte[] cnt = GetPointCount(count * 2);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x0C,0x00,0x10,0x00,
				0x01,0x04,0x00,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				cnt[0],cnt[1]};
            byte[] recvbuffer = SendBuffer(sendbuffer);
            int dataLen = recvbuffer.Length - ReturnValuePosition;
            int retLen = dataLen / 4;
            uint[] ret = new uint[retLen];
            Buffer.BlockCopy(recvbuffer, ReturnValuePosition, ret, 0, dataLen);
            return ret;
        }

        public override uint[] ReadDword(ushort[] point, MelsecDeviceType DeviceType)
        {
            if (point.Length == 0)
                throw new Exception(Globals.NO_DATA_READ);
            ushort count = (ushort)point.Length;
            byte[] sendbuffer = new byte[21 + count * 4];
            byte[] len = GetRequestDataLength(sendbuffer.Length - ERROR_CODE_POSITION);
            byte[] buff1 = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,len[0],len[1],0x10,0x00,
				0x03,0x04,0x00,0x00,0x00,(byte)count};
            Array.Copy(buff1, sendbuffer, buff1.Length);
            for (int i = 0; i < count; ++i)
            {
                byte[] addr = GetPointBytes(point[i]);
                byte[] buff2 = new byte[] { addr[0], addr[1], addr[2], (byte)DeviceType };
                Array.Copy(buff2, 0, sendbuffer, buff1.Length + i * buff2.Length, buff2.Length);
            }
            byte[] recvbuffer = SendBuffer(sendbuffer);
            int dataLen = recvbuffer.Length - ReturnValuePosition;
            int retLen = dataLen / 4;
            uint[] ret = new uint[retLen];
            Buffer.BlockCopy(recvbuffer, ReturnValuePosition, ret, 0, dataLen);
            return ret;
        }

        public override void WriteDword(ushort point, uint val, MelsecDeviceType DeviceType)
        {
            byte[] addr = GetPointBytes(point);
            byte[] dwVal = BitConverter.GetBytes(val);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x10,0x00,0x10,0x00,
				0x01,0x14,0x00,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				0x02,0x00,
				dwVal[0], dwVal[1], dwVal[2], dwVal[3]};
            SendBuffer(sendbuffer);
        }

        public override void WriteDword(ushort point, uint[] val, MelsecDeviceType DeviceType)
        {
            if (val.Length == 0)
                throw new Exception(Globals.NO_DATA_WRITE);
            byte[] addr = GetPointBytes(point);
            ushort count = (ushort)val.Length;
            byte[] cnt = GetPointCount(count * 2);
            byte[] sendbuffer = new byte[25 + count * 4];
            byte[] len = GetRequestDataLength(sendbuffer.Length - ERROR_CODE_POSITION);
            byte[] buff1 = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,len[0],len[1],0x10,0x00,
                0x01,0x14,0x00,0x00,addr[0],addr[1],addr[2],(byte)DeviceType,cnt[0],cnt[1]};
            Array.Copy(buff1, sendbuffer, buff1.Length);
            for (int i = 0; i < count; ++i)
            {
                byte[] rval = BitConverter.GetBytes(val[i]);
                byte[] buff2 = new byte[] { rval[0], rval[1], rval[2], rval[3] };
                Array.Copy(buff2, 0, sendbuffer, buff1.Length + i * buff2.Length, buff2.Length);
            }
            SendBuffer(sendbuffer);
        }

        public override void WriteDword(ushort[] point, uint[] val, MelsecDeviceType DeviceType)
        {
            if (point.Length != val.Length)
                throw new Exception(Globals.SIZE_MISMATCH);
            if (val.Length == 0)
                throw new Exception(Globals.NO_DATA_WRITE);
            ushort count = (ushort)point.Length;
            byte[] sendbuffer = new byte[21 + count * 8];
            byte[] len = GetRequestDataLength(sendbuffer.Length - ERROR_CODE_POSITION);
            byte[] buff1 = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,len[0],len[1],0x10,0x00,
				0x02,0x14,0x00,0x00,0x00,(byte)count};
            Array.Copy(buff1, sendbuffer, buff1.Length);
            for (int i = 0; i < count; ++i)
            {
                byte[] addr = GetPointBytes(point[i]);
                byte[] rval = BitConverter.GetBytes(val[i]);
                byte[] buff2 = new byte[] { addr[0], addr[1], addr[2], (byte)DeviceType,
                                            rval[0], rval[1], rval[2], rval[3]};
                Array.Copy(buff2, 0, sendbuffer, buff1.Length + i * buff2.Length, buff2.Length);
            }
            SendBuffer(sendbuffer);
        }

        public override ushort ReadWord(ushort point, MelsecDeviceType DeviceType)
        {
            byte[] addr = GetPointBytes(point);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x0C,0x00,0x10,0x00,
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
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x0C,0x00,0x10,0x00,
				0x01,0x04,0x00,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				cnt[0],cnt[1]};
            byte[] recvbuffer = SendBuffer(sendbuffer);
            int dataLen = recvbuffer.Length - ReturnValuePosition;
            int retLen = dataLen / 2;
            ushort[] ret = new ushort[retLen];
            Buffer.BlockCopy(recvbuffer, ReturnValuePosition, ret, 0, dataLen);
            return ret;
        }

        public override ushort[] ReadWord(ushort[] point, MelsecDeviceType DeviceType)
        {
            if (point.Length == 0)
                throw new Exception(Globals.NO_DATA_READ);
            ushort count = (ushort)point.Length;
            byte[] sendbuffer = new byte[21 + count * 4];
            byte[] len = GetRequestDataLength(sendbuffer.Length - ERROR_CODE_POSITION);
            byte[] buff1 = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,len[0],len[1],0x10,0x00,
				0x03,0x04,0x00,0x00,(byte)count,0x00};
            Array.Copy(buff1, sendbuffer, buff1.Length);
            for (int i = 0; i < count; ++i)
            {
                byte[] addr = GetPointBytes(point[i]);
                byte[] buff2 = new byte[] { addr[0], addr[1], addr[2], (byte)DeviceType };
                Array.Copy(buff2, 0, sendbuffer, buff1.Length + i * buff2.Length, buff2.Length);
            }
            byte[] recvbuffer = SendBuffer(sendbuffer);
            int dataLen = recvbuffer.Length - ReturnValuePosition;
            int retLen = dataLen / 2;
            ushort[] ret = new ushort[retLen];
            Buffer.BlockCopy(recvbuffer, ReturnValuePosition, ret, 0, dataLen);
            return ret;
        }

        public override void WriteWord(ushort point, ushort val, MelsecDeviceType DeviceType)
        {
            byte[] addr = GetPointBytes(point);
            byte[] wVal = BitConverter.GetBytes(val);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x0E,0x00,0x10,0x00,
				0x01,0x14,0x00,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				0x01,0x00,
				wVal[0], wVal[1]};
            SendBuffer(sendbuffer);
        }

        public override void WriteWord(ushort point, ushort[] val, MelsecDeviceType DeviceType)
        {
            if (val.Length == 0)
                throw new Exception(Globals.NO_DATA_WRITE);
            byte[] addr = GetPointBytes(point);
            ushort count = (ushort)val.Length;
            byte[] cnt = GetPointCount(count);
            byte[] sendbuffer = new byte[25 + count * 2];
            byte[] len = GetRequestDataLength(sendbuffer.Length - ERROR_CODE_POSITION);
            byte[] buff1 = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,len[0],len[1],0x10,0x00,
                0x01,0x14,0x00,0x00,addr[0],addr[1],addr[2],(byte)DeviceType,cnt[0],cnt[1]};
            Array.Copy(buff1, sendbuffer, buff1.Length);
            for (int i = 0; i < count; ++i)
            {
                byte[] wval = BitConverter.GetBytes(val[i]);
                byte[] buff2 = new byte[] { wval[0], wval[1] };
                Array.Copy(buff2, 0, sendbuffer, buff1.Length + i * buff2.Length, buff2.Length);
            }
            SendBuffer(sendbuffer);
        }

        public override void WriteWord(ushort[] point, ushort[] val, MelsecDeviceType DeviceType)
        {
            if (point.Length != val.Length)
                throw new Exception(Globals.SIZE_MISMATCH);
            if (val.Length == 0)
                throw new Exception(Globals.NO_DATA_WRITE);
            ushort count = (ushort)point.Length;
            byte[] sendbuffer = new byte[21 + count * 6];
            byte[] len = GetRequestDataLength(sendbuffer.Length - ERROR_CODE_POSITION);
            byte[] buff1 = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,len[0],len[1],0x10,0x00,
				0x02,0x14,0x00,0x00,(byte)count,0x00};
            Array.Copy(buff1, sendbuffer, buff1.Length);
            for (int i = 0; i < count; ++i)
            {
                byte[] addr = GetPointBytes(point[i]);
                byte[] wval = BitConverter.GetBytes(val[i]);
                byte[] buff2 = new byte[] { addr[0], addr[1], addr[2], (byte)DeviceType,
                                            wval[0], wval[1]};
                Array.Copy(buff2, 0, sendbuffer, buff1.Length + i * buff2.Length, buff2.Length);
            }
            SendBuffer(sendbuffer);
        }

        public override bool ReadByte(ushort point, MelsecDeviceType DeviceType)
        {
            byte[] addr = GetPointBytes(point);
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x0C,0x00,0x10,0x00,
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
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x0C,0x00,0x10,0x00,
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

        public override bool[] ReadByte(ushort[] point, MelsecDeviceType DeviceType)
        {
            if (point.Length == 0)
                throw new Exception(Globals.NO_DATA_READ);
            ushort[] us = ReadWord(point, DeviceType);
            bool[] ret = new bool[us.Length];
            for (int i = 0; i < ret.Length; ++i)
            {
                ret[i] = ((us[i] & 1) == 1);
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
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x0D,0x00,0x10,0x00,
				0x01,0x14,0x01,0x00,
				addr[0],addr[1],addr[2],
				(byte)DeviceType,
				0x01,0x00,
				On};
            SendBuffer(sendbuffer);
        }

        public override void WriteByte(ushort point, bool[] state, MelsecDeviceType DeviceType)
        {
            if (state.Length == 0)
                throw new Exception(Globals.NO_DATA_WRITE);
            if (state.Length == 1)
            {
                WriteByte(point, state[0], DeviceType);
            }
            else
            {
                ushort count = (ushort)state.Length;
                if (count % 2 != 0)
                {
                    throw new Exception(Globals.SIZE_MISMATCH);
                }
                byte[] addr = GetPointBytes(point);
                byte[] cnt = GetPointCount(count);
                byte[] sendbuffer = new byte[25 + count / 2];
                byte[] len = GetRequestDataLength(sendbuffer.Length - ERROR_CODE_POSITION);
                byte[] buff1 = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                    NetNo,PcNo,(byte)destinationCpu,0x03,0x00,len[0],len[1],0x10,0x00,
                    0x01,0x14,0x01,0x00,addr[0],addr[1],addr[2],(byte)DeviceType, cnt[0],cnt[1]};
                Array.Copy(buff1, sendbuffer, buff1.Length);
                for (int i = 0, j = 0; i < count; i += 2, ++j)
                {
                    byte[] buff2 = new byte[1];
                    if (state[i]) buff2[0] |= 0x10;
                    if (state[i + 1]) buff2[0] |= 0x01;
                    Array.Copy(buff2, 0, sendbuffer, buff1.Length + j * buff2.Length, buff2.Length);
                }
                SendBuffer(sendbuffer);
            }
        }

        public override void WriteByte(ushort[] point, bool[] state, MelsecDeviceType DeviceType)
        {
            if (point.Length != state.Length)
                throw new Exception(Globals.SIZE_MISMATCH);
            if (state.Length == 0)
                throw new Exception(Globals.NO_DATA_WRITE);
            ushort count = (ushort)point.Length;
            byte[] sendbuffer = new byte[20 + count * 5];
            byte[] len = GetRequestDataLength(sendbuffer.Length - ERROR_CODE_POSITION);
            byte[] buff1 = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,len[0],len[1],0x10,0x00,
				0x02,0x14,0x01,0x00,(byte)count};
            Array.Copy(buff1, sendbuffer, buff1.Length);
            for (int i = 0; i < count; ++i)
            {
                byte[] addr = GetPointBytes(point[i]);
                byte[] bval = new byte[1];
                if (state[i]) bval[0] = 1;
                byte[] buff2 = new byte[] { addr[0], addr[1], addr[2], (byte)DeviceType, bval[0] };
                Array.Copy(buff2, 0, sendbuffer, buff1.Length + i * buff2.Length, buff2.Length);
            }
            SendBuffer(sendbuffer);
        }

        public override void ErrLedOff()
        {
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x06,0x00,0x10,0x00,
				0x17,0x16,
				0x00,0x00};
            SendBuffer(sendbuffer);
        }

        public override void Run(bool forced, ClearMode mode)
        {
            byte frcd = (forced) ? frcd = 0x03 : frcd = 0x01;
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x0A,0x00,0x10,0x00,
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
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x08,0x00,0x10,0x00,
				0x03,0x10,
				0x00,0x00,
                frcd,0x00};
            SendBuffer(sendbuffer);
        }

        public override void Stop()
        {
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x08,0x00,0x10,0x00,
				0x02,0x10,
				0x00,0x00,
                0x01,0x00};
            SendBuffer(sendbuffer);
        }

        public override void Reset()
        {
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x08,0x00,0x10,0x00,
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
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x08,0x00,0x10,0x00,
				0x05,0x10,
				0x00,0x00,
                0x01,0x00};
            SendBuffer(sendbuffer);
        }

        public override string ReadCPUModelName()
        {
            byte[] sendbuffer = new byte[] {0x54,0x00,SerialNo[0],SerialNo[1],0x00,0x00,
                NetNo,PcNo,(byte)destinationCpu,0x03,0x00,0x06,0x00,0x10,0x00,
				0x01,0x01,
				0x00,0x00};
            byte[] recvbuffer = SendBuffer(sendbuffer);
            int dataLen = recvbuffer.Length - ReturnValuePosition;
            byte[] name = new byte[dataLen];
            Buffer.BlockCopy(recvbuffer, ReturnValuePosition, name, 0, dataLen - 2);
            string ret = System.Text.Encoding.UTF8.GetString(name);
            return ret;
        }
    }
}