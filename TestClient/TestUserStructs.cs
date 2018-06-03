using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Runtime.InteropServices;

namespace TestClientStructs
{
    public struct Variant
    {
        [StructLayout(LayoutKind.Explicit, Size = 8)]
        public struct VariantRec
        {
            [FieldOffset(0)]
            public byte byte0;
            [FieldOffset(1)]
            public byte byte1;
            [FieldOffset(2)]
            public byte byte2;
            [FieldOffset(3)]
            public byte byte3;
            [FieldOffset(4)]
            public byte byte4;
            [FieldOffset(5)]
            public byte byte5;
            [FieldOffset(6)]
            public byte byte6;
            [FieldOffset(7)]
            public byte byte7;
            [FieldOffset(0)]
            public short Short;
            [FieldOffset(2)]
            public short Short2;
            [FieldOffset(4)]
            public short Short3;
            [FieldOffset(6)]
            public short Short4;
            [FieldOffset(0)]
            public ushort Ushort;
            [FieldOffset(2)]
            public ushort Ushort2;
            [FieldOffset(4)]
            public ushort Ushort3;
            [FieldOffset(6)]
            public ushort Ushort4;
            [FieldOffset(0)]
            public int Int;
            [FieldOffset(4)]
            public int IntHi;
            [FieldOffset(0)]
            public uint Uint;
            [FieldOffset(4)]
            public uint UintHi;
            [FieldOffset(0)]
            public long Long;
            [FieldOffset(0)]
            public ulong Ulong;
            [FieldOffset(0)]
            public float Float;
            [FieldOffset(0)]
            public double Double;
        }

        public VariantRec Value;

        private static Variant ReadUsingPointer(byte[] data)
        {
            unsafe
            {
                fixed (byte* packet = &data[0])
                {
                    return *(Variant*)packet;
                }
            }
        }

        static public implicit operator Variant(byte[] value)
        {
            return Variant.ReadUsingPointer(value);
        }
    }

    public class GenBuffer
    {
        public static T[] BlockCopy<S, T>(S[] source)
        {
            int sizeDiv = Marshal.SizeOf(typeof(T)) / Marshal.SizeOf(typeof(S));
            T[] ret = new T[source.Length / sizeDiv];
            Buffer.BlockCopy(source, 0, ret, 0, source.Length);
            return ret;
        }

        public static T[] BlockCopy<T>(byte[] source)
        {
            int sizeDiv = Marshal.SizeOf(typeof(T)) / sizeof(byte);
            T[] ret = new T[source.Length / sizeDiv];
            Buffer.BlockCopy(source, 0, ret, 0, source.Length);
            return ret;
        }
    }

    [TestClass]
    public class TestUserStructs
    {
        [TestMethod]
        public void TestMethod1()
        {
            Variant gp = BitConverter.GetBytes(0x12131415161718);
            gp = new byte[] { 0x01 };
            gp.Value.byte1 = 0x01;
            gp.Value.Double = 3.1415;
            gp.Value.Float = (float)gp.Value.Double;
            gp.Value.Long = long.MaxValue;
        }

        [TestMethod]
        public void TestMethod2()
        {
            long[] l = GenBuffer.BlockCopy<byte, long>(BitConverter.GetBytes(0x1112131415161718));
            int[] i = GenBuffer.BlockCopy<int>(BitConverter.GetBytes(0x1112131415161718));
        }
    }
}
