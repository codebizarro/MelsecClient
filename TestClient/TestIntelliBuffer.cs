using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Net.Melsec;
using System.Runtime.InteropServices;

namespace TestClient
{
    [TestClass]
    public class TestIntelliBuffer : TestCommon
    {
        public TestIntelliBuffer()
            : base(ProtocolType.Melsec3EProtocol, Configuration.Address, 5001)
        {

            //mc.Protocol.DestinationCpu = DestinationCpu.LocalStation;
            //mc.Protocol.KeepConnection = true;
            //mc.Protocol.UseTcp = true;
        }

        int dummyHeadAddress = 0x5000;

        [TestMethod]
        public void ReadIntelliBuffer()
        {
            //Start address = (Buffer memory address x2) + Additional value of a module
            //When specifying Q62DA buffer memory address 18H
            //(18Hx2) + 1008H = 30H + 1008H = 1038H
            //When specifying Q71MB91 buffer memory address 2000H
            //(2000Hx2) + 10000H = 4000H + 10000H = 14400H
            float[] buffer = mc.Protocol.ReadIntelliBuffer<float>(0, 0x10000, 0x2000, 0xFC);
        }

        [TestMethod]
        public void ReadWriteIntelliBuffer()
        {
            Assert.IsTrue(Configuration.DoWrite, "The Writing test are disabled");

            float[] buffer = mc.Protocol.ReadIntelliBuffer<float>(0, 0x10000, 0x2000, 0x2);
            mc.Protocol.WriteIntelliBuffer(0, 0x10000, dummyHeadAddress, buffer);
            buffer = mc.Protocol.ReadIntelliBuffer<float>(0, 0x10000, dummyHeadAddress, 4);

            mc.Protocol.WriteIntelliBuffer<float>(0, 0x10000, dummyHeadAddress, new float[] { 3.1415f, 0.1111f });
            float[] f = mc.Protocol.ReadIntelliBuffer<float>(0, 0x10000, dummyHeadAddress, 2);
            mc.Protocol.WriteIntelliBuffer<float>(0, 0x10000, dummyHeadAddress, new float[] { 0, 0 });

            mc.Protocol.WriteIntelliBuffer<int>(0, 0x10000, dummyHeadAddress, new int[] { 31415, 1111 });
            int[] i = mc.Protocol.ReadIntelliBuffer<int>(0, 0x10000, dummyHeadAddress, 2);
            mc.Protocol.WriteIntelliBuffer<int>(0, 0x10000, dummyHeadAddress, new int[] { 0, 0 });

            mc.Protocol.WriteIntelliBuffer<short>(0, 0x10000, dummyHeadAddress, new short[] { 31415, 1111 });
            short[] s = mc.Protocol.ReadIntelliBuffer<short>(0, 0x10000, dummyHeadAddress, 2);
            mc.Protocol.WriteIntelliBuffer<short>(0, 0x10000, dummyHeadAddress, new short[] { 0, 0 });

            mc.Protocol.WriteIntelliBuffer<byte>(0, 0x10000, dummyHeadAddress, new byte[] { 0x12, 0x34, 0x56, 0x78 });
            mc.Protocol.WriteIntelliBuffer<byte>(0, 0x10000, dummyHeadAddress, BitConverter.GetBytes(2018915346));
            byte[] b = mc.Protocol.ReadIntelliBuffer<byte>(0, 0x10000, dummyHeadAddress, 4);
            mc.Protocol.WriteIntelliBuffer<byte>(0, 0x10000, dummyHeadAddress, new byte[] { 0, 0, 0, 0 });
        }
    }
}
