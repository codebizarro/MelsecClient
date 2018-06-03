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
}
