using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Net.Melsec;

namespace TestClient
{
    [TestClass]
    public class TestEtherBuffer : TestCommon
    {
        public TestEtherBuffer()
            : base(ProtocolType.Melsec3EProtocol, Configuration.Address, 5001)
        {

            //mc.Protocol.DestinationCpu = DestinationCpu.LocalStation;
            //mc.Protocol.KeepConnection = true;
            //mc.Protocol.UseTcp = true;
        }

        int dummyHeadAddress = 0x2680;

        [TestMethod]
        public void ComErrCheckAndClear()
        {
            bool errLed = mc.ErrLed();
            if (errLed)
                mc.Protocol.ErrLedOff();
            errLed = mc.ErrLed();
            Assert.IsFalse(errLed);
        }

        [TestMethod]
        public void ReadEtherBuffer()
        {
            ushort[] buff1 = mc.Protocol.ReadBuffer<ushort>(dummyHeadAddress, 1);
            ushort[] buff2 = mc.Protocol.ReadIntelliBuffer<ushort>(2, 0x10000, dummyHeadAddress, 2);
        }

        [TestMethod]
        public void ReadWriteEtherBuffer()
        {
            Assert.IsTrue(Configuration.DoWrite, "The Writing test are disabled");

            mc.Protocol.WriteBuffer<float>(dummyHeadAddress, new float[] { 3.1415f, 0.1111f });
            float[] f = mc.Protocol.ReadBuffer<float>(dummyHeadAddress, 2);
            mc.Protocol.WriteBuffer<float>(dummyHeadAddress, new float[] { 0, 0 });

            mc.Protocol.WriteBuffer<int>(dummyHeadAddress, new int[] { 31415, 1111 });
            int[] i = mc.Protocol.ReadBuffer<int>(dummyHeadAddress, 2);
            mc.Protocol.WriteBuffer<int>(dummyHeadAddress, new int[] { 0, 0 });

            mc.Protocol.WriteBuffer<short>(dummyHeadAddress, new short[] { 31415, 1111 });
            short[] s = mc.Protocol.ReadBuffer<short>(dummyHeadAddress, 2);
            mc.Protocol.WriteBuffer<short>(dummyHeadAddress, new short[] { 0, 0 });
        }
    }
}
