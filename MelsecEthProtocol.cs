using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace System.Net.Melsec
{
    public abstract class MelsecEthProtocol : MelsecProtocol, IDisposable
    {
        private IPEndPoint EndPoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 5000);
        private readonly int ErrorCodePosition;
        private readonly int MinResponseLength;
        protected readonly int ReturnValuePosition;
        private readonly byte ReturnPacketHeader;
        private readonly byte DataLengthPosition;
        protected byte NetNo = 0x00;
        protected byte PcNo = 0xFF;
        protected byte destinationCpu = (byte)DestinationCpu.LocalStation;
        private IChannel Channel;
        protected byte[] PacketHead;

        protected MelsecEthProtocol(
            string ip,
            ushort port,
            int errorCodePosition,
            int minResponseLength,
            int returnValuePosition,
            byte returnPacketHeader,
            byte dataLengthPosition)
        {
            EndPoint = new IPEndPoint(IPAddress.Parse(ip), port);
            ErrorCodePosition = errorCodePosition;
            MinResponseLength = minResponseLength;
            ReturnValuePosition = returnValuePosition;
            ReturnPacketHeader = returnPacketHeader;
            DataLengthPosition = dataLengthPosition;
        }

        public string Ip
        {
            get
            {
                return EndPoint.Address.ToString();
            }
            set
            {
                CloseChannel();
                EndPoint.Address = IPAddress.Parse(value);
            }
        }

        public ushort Port
        {
            get
            {
                return (ushort)EndPoint.Port;
            }
            set
            {
                CloseChannel();
                if (value > 0)
                    EndPoint.Port = value;
                else throw new Exception("Port number must be greater than zero");
            }
        }

        public DestinationCpu DestinationCpu
        {
            get
            {
                return (DestinationCpu)destinationCpu;
            }
            set
            {
                destinationCpu = (byte)value;
            }
        }

        private bool useTcp;

        public bool UseTcp
        {
            get
            {
                return useTcp;
            }
            set
            {
                useTcp = value;
                CloseChannel();
            }
        }

        public bool KeepConnection { get; set; }

        public abstract void ErrLedOff();

        private void InitChannel()
        {
            if (Channel == null)
            {
                if (!UseTcp)
                {
                    Channel = new UdpChannel(EndPoint);
                }
                else
                {
                    Channel = new TcpChannel(EndPoint);
                }
                Channel.SendTimeout = SendTimeout;
                Channel.ReceiveTimeout = ReceiveTimeout;
            }
        }

        private void CloseChannel()
        {
            if (Channel != null)
            {
                Channel.Dispose();
                Channel = null;
            }
        }

        protected override byte[] SendBuffer(byte[] buffer)
        {
            byte[] outBuff = new byte[0];
            InitChannel();
            outBuff = Channel.Execute(buffer);
            if (!KeepConnection)
                CloseChannel();
            if (outBuff.Length > MinResponseLength)
            {
                if (outBuff[0] != ReturnPacketHeader)
                    throw new Exception(string.Format("Response header PLC is corrupt: {0:X2} ({0}) <> {1:X2} ({1})",
                                                                    ReturnPacketHeader, outBuff[0]));
                LastError = BitConverter.ToUInt16(outBuff, ErrorCodePosition);
                if (LastError != 0)
                    throw new Exception(string.Format("PLC return error code: 0x{0:X4} ({0})", LastError));
                int lenght = BitConverter.ToInt16(outBuff, DataLengthPosition) + ErrorCodePosition;
                if (lenght != outBuff.Length)
                    throw new Exception("PLC returned buffer is corrupt");
            }
            else throw new Exception(string.Format("PLC returned buffer is too small: {0}", outBuff.Length));
            return outBuff;
        }

        public override string ToString()
        {
            return string.Format("{0}:{1} 0x{2:X2}:0x{3:X2}:0x{4:X2}",
                EndPoint.Address, EndPoint.Port, NetNo, PcNo, DestinationCpu);
        }

        private bool disposed = false;

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (disposing)
                {
                    if (Channel != null)
                        Channel.Dispose();
                }
                disposed = true;
            }
        }

        ~MelsecEthProtocol()
        {
            Dispose(false);
        }

        public override T[] BatchReadWord<T>(ushort point, MelsecDeviceType DeviceType, ushort count)
        {
            byte[] addr = GetPointBytes(point);
            int typeSize = System.Runtime.InteropServices.Marshal.SizeOf(typeof(T));
            byte[] cnt = GetPointCount(count * typeSize / 2);
            byte[] sendbuffer = new byte[19 + PacketHead.Length];
            byte[] buff1 = new byte[] {NetNo,PcNo,destinationCpu,0x03,0x00,0x0C,0x00,0x10,0x00,
                0x01,0x04,0x00,0x00,
                addr[0],addr[1],addr[2],
                (byte)DeviceType,
                cnt[0],cnt[1]};
            Array.Copy(PacketHead, sendbuffer, PacketHead.Length);
            Array.Copy(buff1, 0, sendbuffer, PacketHead.Length, buff1.Length);
            byte[] recvbuffer = SendBuffer(sendbuffer);
            int dataLen = recvbuffer.Length - ReturnValuePosition;
            int retLen = dataLen / System.Runtime.InteropServices.Marshal.SizeOf(typeof(T));
            T[] ret = new T[retLen];
            Buffer.BlockCopy(recvbuffer, ReturnValuePosition, ret, 0, dataLen);
            return ret;
        }

        public override void BatchWriteWord<T>(ushort point, T[] val, MelsecDeviceType DeviceType)
        {
            if (val.Length == 0)
                throw new Exception(Globals.NO_DATA_WRITE);
            byte[] addr = GetPointBytes(point);
            int typeSize = System.Runtime.InteropServices.Marshal.SizeOf(typeof(T));
            ushort count = (ushort)(val.Length * typeSize / 2);
            byte[] cnt = GetPointCount(count);
            byte[] sendbuffer = new byte[19 + PacketHead.Length + count * 2];
            byte[] len = GetRequestDataLength(sendbuffer.Length - ErrorCodePosition);
            Array.Copy(PacketHead, sendbuffer, PacketHead.Length);
            byte[] buff1 = new byte[] {NetNo,PcNo,destinationCpu,0x03,0x00,len[0],len[1],0x10,0x00,
                0x01,0x14,0x00,0x00,addr[0],addr[1],addr[2],(byte)DeviceType,cnt[0],cnt[1]};
            Array.Copy(buff1, 0, sendbuffer, PacketHead.Length, buff1.Length);
            byte[] buff2 = new byte[count * 2];
            Buffer.BlockCopy(val, 0, sendbuffer, buff1.Length + PacketHead.Length, buff2.Length);
            SendBuffer(sendbuffer);
        }

        public override T[] RandomReadWord<T>(ushort[] point, MelsecDeviceType DeviceType)
        {
            if (point.Length == 0)
                throw new Exception(Globals.NO_DATA_READ);
            int typeSize = System.Runtime.InteropServices.Marshal.SizeOf(typeof(T));
            ushort count = (ushort)(point.Length);
            byte[] sendbuffer = new byte[15 + PacketHead.Length + count * 4];
            byte[] len = GetRequestDataLength(sendbuffer.Length - ErrorCodePosition);
            byte[] cnt = GetPointCount(count);
            if (typeSize == 4)
            {
                cnt[0] = 0;
                cnt[1] = (byte)count;
            }
            Array.Copy(PacketHead, sendbuffer, PacketHead.Length);
            byte[] buff1 = new byte[] {NetNo,PcNo,destinationCpu,0x03,0x00,len[0],len[1],0x10,0x00,
                0x03,0x04,0x00,0x00,cnt[0],cnt[1]};
            Array.Copy(buff1, 0, sendbuffer, PacketHead.Length, buff1.Length);
            for (int i = 0; i < count; ++i)
            {
                byte[] addr = GetPointBytes((ushort)(point[i]));
                byte[] buff2 = new byte[] { addr[0], addr[1], addr[2], (byte)DeviceType };
                Array.Copy(buff2, 0, sendbuffer, buff1.Length + PacketHead.Length + i * buff2.Length, buff2.Length);
            }
            byte[] recvbuffer = SendBuffer(sendbuffer);
            int dataLen = recvbuffer.Length - ReturnValuePosition;
            int retLen = dataLen / System.Runtime.InteropServices.Marshal.SizeOf(typeof(T));
            T[] ret = new T[retLen];
            Buffer.BlockCopy(recvbuffer, ReturnValuePosition, ret, 0, dataLen);
            return ret;
        }

        public override void RandomWriteWord<T>(ushort[] point, T[] val, MelsecDeviceType DeviceType)
        {
            if (point.Length != val.Length)
                throw new Exception(Globals.SIZE_MISMATCH);
            if (val.Length == 0)
                throw new Exception(Globals.NO_DATA_WRITE);
            int typeSize = System.Runtime.InteropServices.Marshal.SizeOf(typeof(T));
            ushort count = (ushort)point.Length;
            byte[] sendbuffer = new byte[15 + PacketHead.Length + count * (4 + typeSize)];
            byte[] len = GetRequestDataLength(sendbuffer.Length - ErrorCodePosition);
            byte[] cnt = GetPointCount(count);
            if (typeSize == 4)
            {
                cnt[0] = 0;
                cnt[1] = (byte)count;
            }
            Array.Copy(PacketHead, sendbuffer, PacketHead.Length);
            byte[] buff1 = new byte[] {NetNo,PcNo,destinationCpu,0x03,0x00,len[0],len[1],0x10,0x00,
                0x02,0x14,0x00,0x00,cnt[0],cnt[1]};
            Array.Copy(buff1, 0, sendbuffer, PacketHead.Length, buff1.Length);
            for (int i = 0; i < count; ++i)
            {
                byte[] addr = GetPointBytes(point[i]);
                byte[] rval = new byte[typeSize];
                Buffer.BlockCopy(val, i * typeSize, rval, 0, typeSize);
                byte[] buff2 = new byte[] { addr[0], addr[1], addr[2], (byte)DeviceType };
                Array.Copy(buff2, 0, sendbuffer, buff1.Length + PacketHead.Length + i * (buff2.Length + rval.Length), buff2.Length);
                Array.Copy(rval, 0, sendbuffer, buff1.Length + PacketHead.Length + i * (buff2.Length + rval.Length) + buff2.Length, rval.Length);
            }
            SendBuffer(sendbuffer);
        }
    }
}