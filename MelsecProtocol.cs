using System;

namespace System.Net.Melsec
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
                else throw new Exception(Globals.LESS_ZERO_TIMEOUT);
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
                else throw new Exception(Globals.LESS_ZERO_TIMEOUT);
            }
        }

        protected byte[] GetPointBytes(ushort point)
        {
            return GetBytes(point, 3);
        }

        protected byte[] GetPointCount(int count)
        {
            return GetBytes(count, 2);
        }

        protected byte[] GetRequestDataLength(int val)
        {
            return GetBytes(val, 2);
        }

        protected byte[] GetBytes(int val, byte cnt)
        {
            byte[] tmp = BitConverter.GetBytes(val);
            if (tmp.Length < cnt)
            {
                throw new Exception("Array size mismatch");
            }
            byte[] ret = new byte[cnt];
            for (int i = 0; i < ret.Length; i++)
            {
                ret[i] = tmp[i];
            }
            return ret;
        }

        protected byte[] Concat(byte[] array1, byte[] array2)
        {
            byte[] ret = new byte[array1.Length + array2.Length];
            array1.CopyTo(ret, 0);
            array2.CopyTo(ret, array1.Length);
            return ret;
        }

        protected abstract byte[] SendBuffer(byte[] buffer);

        public abstract float ReadReal(ushort point, MelsecDeviceType DeviceType);

        public abstract float[] ReadReal(ushort point, MelsecDeviceType DeviceType, byte count);

        public abstract float[] ReadReal(ushort[] point, MelsecDeviceType DeviceType);

        public abstract void WriteReal(ushort point, float val, MelsecDeviceType DeviceType);

        public abstract void WriteReal(ushort point, float[] val, MelsecDeviceType DeviceType);

        public abstract void WriteReal(ushort[] point, float[] val, MelsecDeviceType DeviceType);

        public abstract uint ReadDword(ushort point, MelsecDeviceType DeviceType);

        public abstract uint[] ReadDword(ushort point, MelsecDeviceType DeviceType, byte count);

        public abstract uint[] ReadDword(ushort[] point, MelsecDeviceType DeviceType);

        public abstract void WriteDword(ushort point, uint val, MelsecDeviceType DeviceType);

        public abstract void WriteDword(ushort point, uint[] val, MelsecDeviceType DeviceType);

        public abstract void WriteDword(ushort[] point, uint[] val, MelsecDeviceType DeviceType);

        public abstract ushort ReadWord(ushort point, MelsecDeviceType DeviceType);

        public abstract ushort[] ReadWord(ushort point, MelsecDeviceType DeviceType, byte count);
        
        public abstract ushort[] ReadWord(ushort[] point, MelsecDeviceType DeviceType);

        public abstract void WriteWord(ushort point, ushort val, MelsecDeviceType DeviceType);

        public abstract void WriteWord(ushort point, ushort[] val, MelsecDeviceType DeviceType);

        public abstract void WriteWord(ushort[] point, ushort[] val, MelsecDeviceType DeviceType);

        public abstract bool ReadByte(ushort point, MelsecDeviceType DeviceType);

        public abstract bool[] ReadByte(ushort point, MelsecDeviceType DeviceType, byte count);

        public abstract bool[] ReadByte(ushort[] point, MelsecDeviceType DeviceType);

        public abstract void WriteByte(ushort point, bool state, MelsecDeviceType DeviceType);

        public abstract void WriteByte(ushort point, bool[] state, MelsecDeviceType DeviceType);

        public abstract void WriteByte(ushort[] point, bool[] state, MelsecDeviceType DeviceType);

        public abstract void Run(bool forced, ClearMode mode);

        public abstract void Pause(bool forced);

        public abstract void Stop();

        public abstract void Reset();

        public abstract void LatchClear();

        public abstract string ReadCPUModelName();

        public abstract byte[] ReadIntelliBuffer(ushort module, int headAddress, int address, byte count);

        public abstract void WriteIntelliBuffer(ushort module, int headAddress, int address, byte[] val);

        public abstract ushort[] ReadBuffer(int address, byte count);

        public abstract void WriteBuffer(int address, ushort[] val);

        public abstract T[] BatchReadWord<T>(ushort point, MelsecDeviceType DeviceType, ushort count);

        public abstract void BatchWriteWord<T>(ushort point, T[] val, MelsecDeviceType DeviceType);

        public abstract T[] RandomReadWord<T>(ushort[] point, MelsecDeviceType DeviceType);

        public abstract void RandomWriteWord<T>(ushort[] point, T[] val, MelsecDeviceType DeviceType);
    }
}