using System;
using System.Globalization;

namespace Melsec
{
    public abstract class MelsecClient
    {
        protected readonly MelsecProtocol melsecProtocol;

        protected MelsecClient(MelsecProtocol protocol, int receiveTimeout, int sendTimeout)
        {
            melsecProtocol = protocol;
            melsecProtocol.SendTimeout = sendTimeout;
            melsecProtocol.ReceiveTimeout = receiveTimeout;
        }

        public bool SetQTime(DateTime datetime)
        {
            string sd210 = datetime.ToString("yyMM");
            ushort id210 = ushort.Parse(sd210, NumberStyles.HexNumber);
            string sd211 = datetime.ToString("ddHH");
            ushort id211 = ushort.Parse(sd211, NumberStyles.HexNumber);
            string sd212 = datetime.ToString("mmss");
            ushort id212 = ushort.Parse(sd212, NumberStyles.HexNumber);
            string sd213 = datetime.ToString("yyyy");
            sd213 = sd213.Substring(0, 2);
            sd213 += "0";
            sd213 += datetime.DayOfWeek.ToString("d");
            ushort id213 = ushort.Parse(sd213, NumberStyles.HexNumber);
            int d210 = (id211 << 16) | id210;
            int d212 = (id213 << 16) | id212;
            melsecProtocol.WriteByte(213, false, MelsecDeviceType.SpecialRelay);
            melsecProtocol.WriteByte(211, false, MelsecDeviceType.SpecialRelay);
            melsecProtocol.WriteDword(210, (uint)d210, MelsecDeviceType.SpecialRegister);
            melsecProtocol.WriteDword(212, (uint)d212, MelsecDeviceType.SpecialRegister);
            melsecProtocol.WriteByte(210, false, MelsecDeviceType.SpecialRelay);
            melsecProtocol.WriteByte(210, true, MelsecDeviceType.SpecialRelay);
            melsecProtocol.WriteByte(210, false, MelsecDeviceType.SpecialRelay);
            return !melsecProtocol.ReadByte(211, MelsecDeviceType.SpecialRelay);
        }

        private void BcdToInt(ref uint bcd)
        {
            bcd = uint.Parse(bcd.ToString("x"));
        }

        public DateTime GetQTime()
        {
            melsecProtocol.WriteByte(213, true, MelsecDeviceType.SpecialRelay);
            uint d210 = melsecProtocol.ReadDword(210, MelsecDeviceType.SpecialRegister);
            uint d212 = melsecProtocol.ReadDword(212, MelsecDeviceType.SpecialRegister);
            melsecProtocol.WriteByte(213, false, MelsecDeviceType.SpecialRelay);
            uint Year = (((d212 >> 16) & 0xFF00) | ((d210 >> 8) & 0xFF));
            uint Month = (d210 & 0xFF);
            uint Day = ((d210 >> 24) & 0xFF);
            uint Hour = ((d210 >> 16) & 0xFF);
            uint Minute = ((d212 >> 8) & 0xFF);
            uint Second = (d212 & 0xFF);
            //uint DayOfWeek = ((id212 >> 16) & 0xFF);
            BcdToInt(ref Year);
            BcdToInt(ref Month);
            BcdToInt(ref Day);
            BcdToInt(ref Hour);
            BcdToInt(ref Minute);
            BcdToInt(ref Second);
            //HexInt(ref DayOfWeek);
            return new DateTime((int)Year, (int)Month, (int)Day, (int)Hour, (int)Minute, (int)Second);
        }
    }
}