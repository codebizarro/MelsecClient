using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace System.Net.Melsec
{
    public abstract class MelsecEthProtocol : MelsecProtocol, IDisposable
    {
        private IPEndPoint ipep = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 5000);
        private readonly int ErrorCodePosition;
        private readonly int MinResponseLength;
        protected readonly int ReturnValuePosition;
        private readonly byte ReturnPacketHeader;
        protected byte NetNo = 0x00;
        protected byte PcNo = 0xFF;
        protected byte destinationCpu = (byte)DestinationCpu.LocalStation;
        private IChannel channel;

        protected MelsecEthProtocol(string ip, ushort port, int errorCodePosition, int minResponseLength, int returnValuePosition, byte returnPacketHeader)
        {
            ipep = new IPEndPoint(IPAddress.Parse(ip), port);
            ErrorCodePosition = errorCodePosition;
            MinResponseLength = minResponseLength;
            ReturnValuePosition = returnValuePosition;
            ReturnPacketHeader = returnPacketHeader;
        }

        public string Ip
        {
            get
            {
                return ipep.Address.ToString();
            }
            set
            {
                ipep.Address = IPAddress.Parse(value);
            }
        }

        public ushort Port
        {
            get
            {
                return (ushort)ipep.Port;
            }
            set
            {
                if (value > 0)
                    ipep.Port = value;
                else throw new Exception("Port number must be greater than zero");
            }
        }

        public byte NetworkNo
        {
            get
            {
                return NetNo;
            }
            set
            {
                NetNo = value;
            }
        }

        public byte StationNo
        {
            get
            {
                return PcNo;
            }
            set
            {
                PcNo = value;
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

        public bool UseTcp { get; set; }

        public abstract void ErrLedOff();

        protected override byte[] SendBuffer(byte[] buffer)
        {
            byte[] outBuff = new byte[0];
            if (channel == null)
            {
                if (!UseTcp)
                {
                    channel = new UdpChannel(ipep);
                }
                else
                {
                    channel = new TcpChannel(ipep);
                }
                channel.SendTimeout = SendTimeout;
                channel.ReceiveTimeout = ReceiveTimeout;
            }
            outBuff = channel.Execute(buffer);
            if (outBuff.Length > MinResponseLength)
            {
                if (outBuff[0] != ReturnPacketHeader)
                    throw new Exception(string.Format("Response header PLC is corrupt: {0:X2} ({0}) <> {1:X2} ({1})",
                                                                    ReturnPacketHeader, outBuff[0]));
                LastError = BitConverter.ToUInt16(outBuff, ErrorCodePosition);
                if (LastError != 0)
                    throw new Exception(string.Format("PLC return error code: 0x{0:X4} ({0})", LastError));
            }
            else throw new Exception(string.Format("PLC returned buffer is too small: {0}", outBuff.Length));
            return outBuff;
        }

        public override string ToString()
        {
            return string.Format("{0}:{1} 0x{2:X2}:0x{3:X2}:0x{4:X2}", Ip, Port, NetworkNo, StationNo, DestinationCpu);
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
                    //component.Dispose();
                    channel.Dispose();
                }
                disposed = true;
            }
        }

        ~MelsecEthProtocol()
        {
            Dispose(false);
        }
    }
}