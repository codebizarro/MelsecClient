using System;
using System.Collections.Generic;
using System.Net.Melsec;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;

namespace TestClient
{
    public class TestCommon : IDisposable
    {
        private ushort dummyReg = 3500;
        private ushort dummyMer = 3500;
        private ushort[] arrayReg;
        private ushort[] arrayReg2;
        private ushort valShort;
        private uint valInt;
        private float valFloat;
        private ushort[] arrayShort;
        private uint[] arrayInt;
        private float[] arrayFloat;
        private bool[] arrayBoolTrue;
        private bool[] arrayBoolFalse;
        private byte arrSize = 128;
        protected string plcModel = string.Empty;
        protected MelsecEthClient mc;

        public string Debug
        {
            set
            {
                System.Diagnostics.Debug.WriteLine(value);
            }
        }

        public TestCommon(ProtocolType protocol, string ip, ushort port)
        {
            mc = new MelsecEthClient(protocol, ip, port, 1000, 1000);
            Random _rand = new Random();
            arrayShort = Enumerable.Range(0, arrSize)
                        .Select(r => (ushort)_rand.Next(0, ushort.MaxValue))
                        .ToArray();
            arrayInt = Enumerable.Range(0, arrSize)
                        .Select(r => (uint)_rand.Next(0, int.MaxValue))
                        .ToArray();
            arrayFloat = Enumerable.Range(0, arrSize)
                        .Select(r => (float)_rand.Next(int.MinValue, int.MaxValue))
                        .ToArray();
            arrayReg = Enumerable.Range(dummyReg - 1, arrSize)
                        .Select(r => (ushort)(r + 1))
                        .ToArray();
            arrayReg2 = Enumerable.Range(dummyReg - 1, arrSize * 2)
                        .Select(r => (ushort)(r + 1))
                        .Where(r => r % 2 == 0)
                        .ToArray();
            arrayBoolFalse = Enumerable.Range(dummyReg - 1, arrSize)
                        .Select(r => (bool)false)
                        .ToArray();
            arrayBoolTrue = Enumerable.Range(dummyReg - 1, arrSize)
                        .Select(r => (bool)true)
                        .ToArray();
            valShort = (ushort)_rand.Next(ushort.MaxValue);
            valInt = (uint)_rand.Next(int.MaxValue);
            valFloat = (float)_rand.NextDouble();
        }

        public void GetQTime()
        {
            //#warning Метод отключен
            //            return;
            DateTime dt = mc.GetQTime();
            Assert.IsTrue(DateTime.TryParse(dt.ToString(), out dt));
        }

        public void SetQTime()
        {
            //#warning Метод отключен
            //            return;
            DateTime testDateTime = new DateTime(1984, 3, 8, 16, 20, 33);
            Assert.IsTrue(mc.SetQTime(testDateTime));
            DateTime dt = mc.GetQTime();
            Assert.IsTrue((testDateTime - dt).Minutes < 10);
            Assert.IsTrue(mc.SetQTime(DateTime.Now));
            dt = mc.GetQTime();
            Assert.IsTrue((dt - DateTime.Now).Minutes < 10);
        }

        public void GetModel()
        {
            //#warning Метод отключен
            //            return;
            string model = mc.Protocol.ReadCPUModelName();
            Assert.AreEqual(model.Substring(0, plcModel.Length), plcModel, false);
        }

        public void ByteReadWriteOne()
        {
            mc.Protocol.WriteByte(dummyMer, false, MelsecDeviceType.InternalRelay);
            Assert.IsFalse(mc.Protocol.ReadByte(dummyMer, MelsecDeviceType.InternalRelay));
            mc.Protocol.WriteByte(dummyMer, true, MelsecDeviceType.InternalRelay);
            Assert.IsTrue(mc.Protocol.ReadByte(dummyMer, MelsecDeviceType.InternalRelay));
        }

        public void ByteReadWriteBatch()
        {
            mc.Protocol.WriteByte(dummyMer, arrayBoolFalse, MelsecDeviceType.InternalRelay);
            Assert.IsTrue(ArraysEqual(arrayBoolFalse, mc.Protocol.ReadByte(dummyMer, MelsecDeviceType.InternalRelay, arrSize)));
            mc.Protocol.WriteByte(dummyMer, arrayBoolTrue, MelsecDeviceType.InternalRelay);
            Assert.IsTrue(ArraysEqual(arrayBoolTrue, mc.Protocol.ReadByte(dummyMer, MelsecDeviceType.InternalRelay, arrSize)));
        }

        public void ByteReadWriteRandom()
        {
            mc.Protocol.WriteByte(arrayReg, arrayBoolFalse, MelsecDeviceType.InternalRelay);
            Assert.IsTrue(ArraysEqual(arrayBoolFalse, mc.Protocol.ReadByte(arrayReg, MelsecDeviceType.InternalRelay)));
            mc.Protocol.WriteByte(arrayReg, arrayBoolTrue, MelsecDeviceType.InternalRelay);
            Assert.IsTrue(ArraysEqual(arrayBoolTrue, mc.Protocol.ReadByte(arrayReg, MelsecDeviceType.InternalRelay)));
        }

        public void WordReadWriteOne()
        {
            mc.Protocol.WriteWord(dummyReg, valShort, MelsecDeviceType.DataRegister);
            Assert.AreEqual(valShort, mc.Protocol.ReadWord(dummyReg, MelsecDeviceType.DataRegister));
        }

        public void WordReadWriteBatch()
        {
            mc.Protocol.WriteWord(dummyReg, arrayShort, MelsecDeviceType.DataRegister);
            Assert.IsTrue(ArraysEqual<ushort>(arrayShort, mc.Protocol.ReadWord(dummyReg, MelsecDeviceType.DataRegister, arrSize)));
        }

        public void WordReadWriteRandom()
        {
            mc.Protocol.WriteWord(arrayReg, arrayShort, MelsecDeviceType.DataRegister);
            Assert.IsTrue(ArraysEqual<ushort>(arrayShort, mc.Protocol.ReadWord(arrayReg, MelsecDeviceType.DataRegister)));
        }

        public void DwordReadWriteOne()
        {
            mc.Protocol.WriteDword(dummyReg, valInt, MelsecDeviceType.DataRegister);
            Assert.AreEqual(valInt, mc.Protocol.ReadDword(dummyReg, MelsecDeviceType.DataRegister));
        }

        public void DwordReadWriteBatch()
        {
            mc.Protocol.WriteDword(dummyReg, arrayInt, MelsecDeviceType.DataRegister);
            Assert.IsTrue(ArraysEqual<uint>(arrayInt, mc.Protocol.ReadDword(dummyReg, MelsecDeviceType.DataRegister, arrSize)));
        }

        public void DwordReadWriteRandom()
        {
            mc.Protocol.WriteDword(arrayReg2, arrayInt, MelsecDeviceType.DataRegister);
            Assert.IsTrue(ArraysEqual<uint>(arrayInt, mc.Protocol.ReadDword(arrayReg2, MelsecDeviceType.DataRegister)));
        }

        public void FloatReadWriteOne()
        {
            mc.Protocol.WriteReal(dummyReg, valFloat, MelsecDeviceType.DataRegister);
            Assert.AreEqual(valFloat, mc.Protocol.ReadReal(dummyReg, MelsecDeviceType.DataRegister));
        }

        public void FloatReadWriteBatch()
        {
            mc.Protocol.WriteReal(dummyReg, arrayFloat, MelsecDeviceType.DataRegister);
            Assert.IsTrue(ArraysEqual<float>(arrayFloat, mc.Protocol.ReadReal(dummyReg, MelsecDeviceType.DataRegister, arrSize)));
        }

        public void FloatReadWriteRandom()
        {
            mc.Protocol.WriteReal(arrayReg2, arrayFloat, MelsecDeviceType.DataRegister);
            Assert.IsTrue(ArraysEqual<float>(arrayFloat, mc.Protocol.ReadReal(arrayReg2, MelsecDeviceType.DataRegister)));
        }

        static bool ArraysEqual<T>(T[] a1, T[] a2)
        {
            if (ReferenceEquals(a1, a2))
                return true;

            if (a1 == null || a2 == null)
                return false;

            if (a1.Length != a2.Length)
                return false;

            EqualityComparer<T> comparer = EqualityComparer<T>.Default;
            for (int i = 0; i < a1.Length; i++)
            {
                if (!comparer.Equals(a1[i], a2[i])) return false;
            }
            return true;
            //var arraysAreEqual = Enumerable.SequenceEqual(a1, a2);
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
                    mc.Protocol.Dispose();
                }
                disposed = true;
            }
        }

        ~TestCommon()
        {
            Dispose(false);
        }
    }
}
