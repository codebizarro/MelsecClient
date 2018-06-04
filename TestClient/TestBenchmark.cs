using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net.Melsec;

namespace TestClient
{
    [TestClass]
    public class TestBenchmark : TestCommon
    {

        public TestBenchmark()
            : base(ProtocolType.Melsec3EProtocol, Configuration.Address, 5002)
        {
            //mc.Protocol.DestinationCpu = DestinationCpu.StandbySystem;
            mc.Protocol.UseTcp = true;
            mc.Protocol.KeepConnection = true;
        }

        [TestMethod]
        public void BenchmarkTCP()
        {
            mc.Protocol.UseTcp = true;
            mc.Protocol.Port = 5002;
            base.ByteReadWriteOne();
            base.ByteReadWriteBatch();
            base.ByteReadWriteRandom();
            base.WordReadWriteOne();
            base.WordReadWriteBatch();
            base.WordReadWriteRandom();
            base.DwordReadWriteOne();
            base.DwordReadWriteBatch();
            base.DwordReadWriteRandom();
            base.FloatReadWriteOne();
            base.FloatReadWriteBatch();
            base.FloatReadWriteRandom();
            //base.GetQTime();
            //base.SetQTime();
        }

        [TestMethod]
        public void BenchmarkUDP()
        {
            mc.Protocol.UseTcp = false;
            mc.Protocol.Port = 5001;
            base.ByteReadWriteOne();
            base.ByteReadWriteBatch();
            base.ByteReadWriteRandom();
            base.WordReadWriteOne();
            base.WordReadWriteBatch();
            base.WordReadWriteRandom();
            base.DwordReadWriteOne();
            base.DwordReadWriteBatch();
            base.DwordReadWriteRandom();
            base.FloatReadWriteOne();
            base.FloatReadWriteBatch();
            base.FloatReadWriteRandom();
            //base.GetQTime();
            //base.SetQTime();
        }
    }
}
