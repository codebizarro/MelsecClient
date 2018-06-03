using System.Net.Sockets;

namespace System.Net.Melsec
{
    class UdpChannel : IChannel
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

        private bool disposed;

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
}
