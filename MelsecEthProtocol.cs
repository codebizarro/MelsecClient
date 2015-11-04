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

        protected MelsecEthProtocol(string ip, ushort port, int errorCodePosition, int minResponseLength, int returnValuePosition, byte returnPacketHeader, byte dataLengthPosition)
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
    }
}