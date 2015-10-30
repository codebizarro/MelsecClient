using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace System.Net.Melsec
{
    public abstract class MelsecEthProtocol : MelsecProtocol
    {
        private IPEndPoint ipep = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 5000);
        private readonly int ErrorCodePosition;
        private readonly int MinResponseLength;
        protected readonly int ReturnValuePosition;
        private readonly byte ReturnPacketHeader;
        protected byte NetNo = 0x00;
        protected byte PcNo = 0xFF;
        protected byte destinationCpu = (byte)DestinationCpu.LocalStation;

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
            if (!UseTcp)
            {
                using (UdpClient uc = new UdpClient())
                {
                    uc.Client.SendTimeout = SendTimeout;
                    uc.Client.ReceiveTimeout = ReceiveTimeout;
                    uc.Connect(ipep);
                    uc.Send(buffer, buffer.Length);
                    outBuff = uc.Receive(ref ipep);
                    uc.Close();
                }
            }
            else
            {
                using (TcpClient tc = new TcpClient())
                {
                    tc.Client.SendTimeout = SendTimeout;
                    tc.Client.ReceiveTimeout = ReceiveTimeout;
                    tc.Connect(ipep);
                    NetworkStream stream = tc.GetStream();
                    stream.Write(buffer, 0, buffer.Length);
                    if (stream.CanRead)
                    {
                        System.Collections.Generic.List<byte> lst = new Collections.Generic.List<byte>();
                        byte[] header = new byte[ErrorCodePosition];
                        int n = 0;
                        n = stream.Read(header, 0, header.Length);
                        if (n == ErrorCodePosition)
                        {
                            lst.AddRange(header);
                            short lenght = BitConverter.ToInt16(header, ErrorCodePosition - 2);
                            byte[] buff = new byte[lenght];
                            do
                            {
                                n = stream.Read(buff, 0, buff.Length);
                                for (int i = 0; i < n; ++i)
                                    lst.Add(buff[i]);
                            }
                            while (stream.DataAvailable);
                            outBuff = lst.ToArray();
                        }
                    }
                    stream.Close();
                    tc.Close();
                }
            }
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
    }
}