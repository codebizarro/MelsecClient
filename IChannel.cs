using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace System.Net.Melsec
{
    public interface IChannel : IDisposable
    {
        byte[] Execute(byte[] buffer);

        int SendTimeout
        {
            get;
            set;
        }

        int ReceiveTimeout
        {
            get;
            set;
        }
    }

    internal class UdpChannel : IChannel
    {
        private UdpClient Client;
        private IPEndPoint EndPoint;

        public UdpChannel(IPEndPoint endpoint)
        {
            EndPoint = endpoint;
            Client = new UdpClient();
            Client.Connect(endpoint);
        }

        public byte[] Execute(byte[] buffer)
        {
            Client.Send(buffer, buffer.Length);
            return Client.Receive(ref EndPoint);
        }

        public int SendTimeout
        {
            get
            {
                return Client.Client.SendTimeout;
            }
            set
            {
                Client.Client.SendTimeout = value;
            }
        }

        public int ReceiveTimeout
        {
            get
            {
                return Client.Client.ReceiveTimeout;
            }
            set
            {
                Client.Client.ReceiveTimeout = value;
            }
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
                    if (Client != null)
                    {
                        Client.Close();
                        Client = null;
                    }
                }
                disposed = true;
            }
        }

        ~UdpChannel()
        {
            Dispose(false);
        }
    }

    internal class TcpChannel : IChannel
    {
        private Socket Client;

        public TcpChannel(IPEndPoint endpoint)
        {
            Client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, Sockets.ProtocolType.Tcp);
            //Client.LingerState = new LingerOption(true, 0);
            //Client.NoDelay = true;
            //Client.Blocking = true;
            Client.Connect(endpoint);
        }

        public byte[] Execute(byte[] buffer)
        {
            Client.Send(buffer, 0, buffer.Length, SocketFlags.None);
            System.Threading.Thread.Sleep(100);
            System.Collections.Generic.List<byte> lst = new Collections.Generic.List<byte>();
            {
                byte[] buff = new byte[Client.Available];
                int n = 0;
                n = Client.Receive(buff, 0, Client.Available, SocketFlags.None);
                lst.AddRange(buff);
            }
            return lst.ToArray();
        }

        public int SendTimeout
        {
            get
            {
                return Client.SendTimeout;
            }
            set
            {
                Client.SendTimeout = value;
            }
        }

        public int ReceiveTimeout
        {
            get
            {
                return Client.ReceiveTimeout;
            }
            set
            {
                Client.ReceiveTimeout = value;
            }
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
                    if (Client != null)
                    {
                        Client.Shutdown(SocketShutdown.Both);
                        Client.Close();
                        Client = null;
                    }
                }
                disposed = true;
            }
        }

        ~TcpChannel()
        {
            Dispose(false);
        }
    }
}
