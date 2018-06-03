using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net.Melsec;

namespace TestClient
{
    [TestClass]
    public class TestRedundantUDP : TestCommon
    {
        public TestRedundantUDP()
            : base(ProtocolType.Melsec3EProtocol, "192.168.22.62", 5001)
        {
            mc.Protocol.DestinationCpu = DestinationCpu.StandbySystem;
            plcModel = "Q25PRHCPU";
            mc.Protocol.KeepConnection = true;
        }

        //[TestMethod]
        //public new void GetQTime()
        //{
        //    base.GetQTime();
        //}

        //[TestMethod]
        //public new void SetQTime()
        //{
        //    base.SetQTime();
        //}

        [TestMethod]
        public new void GetModel()
        {
            base.GetModel();
        }

        [TestMethod]
        public new void ByteReadWriteOne()
        {
            base.ByteReadWriteOne();
        }

        [TestMethod]
        public new void ByteReadWriteBatch()
        {
            base.ByteReadWriteBatch();
        }

        [TestMethod]
        public new void ByteReadWriteRandom()
        {
            base.ByteReadWriteRandom();
        }

        [TestMethod]
        public new void WordReadWriteOne()
        {
            base.WordReadWriteOne();
        }

        [TestMethod]
        public new void WordReadWriteBatch()
        {
            base.WordReadWriteBatch();
        }

        [TestMethod]
        public new void WordReadWriteRandom()
        {
            base.WordReadWriteRandom();
        }

        [TestMethod]
        public new void DwordReadWriteOne()
        {
            base.DwordReadWriteOne();
        }

        [TestMethod]
        public new void DwordReadWriteBatch()
        {
            base.DwordReadWriteBatch();
        }

        [TestMethod]
        public new void DwordReadWriteRandom()
        {
            base.DwordReadWriteRandom();
        }

        [TestMethod]
        public new void FloatReadWriteOne()
        {
            base.FloatReadWriteOne();
        }

        [TestMethod]
        public new void FloatReadWriteBatch()
        {
            base.FloatReadWriteBatch();
        }

        [TestMethod]
        public new void FloatReadWriteRandom()
        {
            base.FloatReadWriteRandom();
        }
    }

    [TestClass]
    public class TestRedundantTCP : TestCommon
    {
        public TestRedundantTCP()
            : base(ProtocolType.Melsec3EProtocol, "192.168.22.62", 5002)
        {
            mc.Protocol.DestinationCpu = DestinationCpu.StandbySystem;
            plcModel = "Q25PRHCPU";
            mc.Protocol.UseTcp = true;
            mc.Protocol.KeepConnection = true;
        }

        //[TestMethod]
        //public new void GetQTime()
        //{
        //    base.GetQTime();
        //}

        //[TestMethod]
        //public new void SetQTime()
        //{
        //    base.SetQTime();
        //}

        [TestMethod]
        public new void GetModel()
        {
            base.GetModel();
        }

        [TestMethod]
        public new void ByteReadWriteOne()
        {
            base.ByteReadWriteOne();
        }

        [TestMethod]
        public new void ByteReadWriteBatch()
        {
            base.ByteReadWriteBatch();
        }

        [TestMethod]
        public new void ByteReadWriteRandom()
        {
            base.ByteReadWriteRandom();
        }

        [TestMethod]
        public new void WordReadWriteOne()
        {
            base.WordReadWriteOne();
        }

        [TestMethod]
        public new void WordReadWriteBatch()
        {
            base.WordReadWriteBatch();
        }

        [TestMethod]
        public new void WordReadWriteRandom()
        {
            base.WordReadWriteRandom();
        }

        [TestMethod]
        public new void DwordReadWriteOne()
        {
            base.DwordReadWriteOne();
        }

        [TestMethod]
        public new void DwordReadWriteBatch()
        {
            base.DwordReadWriteBatch();
        }

        [TestMethod]
        public new void DwordReadWriteRandom()
        {
            base.DwordReadWriteRandom();
        }

        [TestMethod]
        public new void FloatReadWriteOne()
        {
            base.FloatReadWriteOne();
        }

        [TestMethod]
        public new void FloatReadWriteBatch()
        {
            base.FloatReadWriteBatch();
        }

        [TestMethod]
        public new void FloatReadWriteRandom()
        {
            base.FloatReadWriteRandom();
        }
    }
}
