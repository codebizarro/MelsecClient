using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace System.Net.Melsec
{
    public interface IChannel: IDisposable
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
        private NetworkStream stream;

        public TcpChannel(IPEndPoint endpoint)
        {
            Client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, Sockets.ProtocolType.Tcp);
            Client.Connect(endpoint);
            stream = new NetworkStream(Client);
        }

        public byte[] Execute(byte[] buffer)
        {
            if (stream.CanWrite)
            {
                stream.Write(buffer, 0, buffer.Length);
                stream.Flush();
            }
            System.Collections.Generic.List<byte> lst = new Collections.Generic.List<byte>();
            if (stream.CanRead)
            {
                byte[] buff = new byte[1024];
                int n = 0;
                do
                {
                    n = stream.Read(buff, 0, buff.Length);
                    for (int i = 0; i < n; ++i)
                        lst.Add(buff[i]);
                }
                while (stream.DataAvailable);
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
                    if (stream != null)
                    {
                        stream.Close();
                        stream = null;
                    }
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
