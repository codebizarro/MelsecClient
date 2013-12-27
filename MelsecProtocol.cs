using System;

namespace Melsec
{
    public abstract class MelsecProtocol
    {
        private ushort lastError = 0;
        private int receiveTimeout = 1000;
        private int sendTimeout = 1000;

        public ushort LastError
        {
            get
            {
                return lastError;
            }
            protected set
            {
                lastError = value;
            }
        }

        public int ReceiveTimeout
        {
            get
            {
                return receiveTimeout;
            }
            set
            {
                if (value > 0)
                    receiveTimeout = value;
                else throw new Exception("Receive timeout must be greater than zero");
            }
        }

        public int SendTimeout
        {
            get
            {
                return sendTimeout;
            }
            set
            {
                if (value > 0)
                    sendTimeout = value;
                else throw new Exception("Send timeout must be greater than zero");
            }
        }

        protected byte[] GetPointBytes(ushort point)
        {
            byte[] tmp = BitConverter.GetBytes(point);
            //if (tmp.Length == 0) return new byte[0];
            byte[] addr = new byte[3];
            for (int i = 0; i < tmp.Length; i++)
            {
                addr[i] = tmp[i];
            }
            return addr;
        }

        protected byte[] GetPointCount(ushort count)
        {
            byte[] tmp = BitConverter.GetBytes(count);
            //if (tmp.Length == 0) return new byte[0];
            byte[] cnt = new byte[2];
            for (int i = 0; i < tmp.Length; i++)
            {
                cnt[i] = tmp[i];
            }
            return cnt;
        }

        protected abstract byte[] SendBuffer(byte[] buffer);

        public abstract float ReadReal(ushort point, MelsecDeviceType DeviceType);

        public abstract float[] ReadReal(ushort point, MelsecDeviceType DeviceType, byte count);

        public abstract void WriteReal(ushort point, float val, MelsecDeviceType DeviceType);

        public abstract uint ReadDword(ushort point, MelsecDeviceType DeviceType);

        public abstract uint[] ReadDword(ushort point, MelsecDeviceType DeviceType, byte count);

        public abstract void WriteDword(ushort point, uint val, MelsecDeviceType DeviceType);

        public abstract ushort ReadWord(ushort point, MelsecDeviceType DeviceType);

        public abstract ushort[] ReadWord(ushort point, MelsecDeviceType DeviceType, byte count);

        public abstract void WriteWord(ushort point, ushort val, MelsecDeviceType DeviceType);

        public abstract bool ReadByte(ushort point, MelsecDeviceType DeviceType);

        public abstract bool[] ReadByte(ushort point, MelsecDeviceType DeviceType, byte count);

        public abstract void WriteByte(ushort point, bool state, MelsecDeviceType DeviceType);
    }
}