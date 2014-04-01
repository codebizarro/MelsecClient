using System;
using System.Globalization;

namespace System.Net.Melsec
{
    public abstract class MelsecClient
    {
        protected readonly MelsecProtocol melsecProtocol;

        protected MelsecClient(ProtocolType protocoltype, string ip, ushort port, int receiveTimeout, int sendTimeout)
        {
            switch (protocoltype)
            {
                case ProtocolType.Melsec3EProtocol:
                    melsecProtocol = new Melsec3EProtocol(ip, port);
                    break;
                case ProtocolType.Melsec4EProtocol:
                    melsecProtocol = new Melsec4EProtocol(ip, port);
                    break;
            }
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

        public CpuStatus ReadCPUStatus()
        {
            ushort status = melsecProtocol.ReadWord(203, MelsecDeviceType.SpecialRegister);
            int[] bStatus = new int[1];
            bStatus[0] = status & ((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 15));
            switch (bStatus[0])
            {
                case 0: return CpuStatus.RUN;
                case 1: return CpuStatus.STEPRUN;
                case 2: return CpuStatus.STOP;
                case 3: return CpuStatus.PAUSE;
                default: return CpuStatus.NONE;
            }
        }
        
        public SwitchStatus ReadSwitchStatus()
        {
            ushort status = melsecProtocol.ReadWord(200, MelsecDeviceType.SpecialRegister);
            int[] bStatus = new int[1];
            bStatus[0] = status & ((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 15));
            switch (bStatus[0])
            {
                case 0: return SwitchStatus.RUN;
                case 1: return SwitchStatus.STOP;
                case 2: return SwitchStatus.LCLR;
                default: return SwitchStatus.NONE;
            }
        }
        
        public StopPauseCause ReadStopPauseCause()
        {
            ushort status = melsecProtocol.ReadWord(203, MelsecDeviceType.SpecialRegister);
            int[] bStatus = new int[1];
            bStatus[0] = status & ((1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 15));
            bStatus[0] >>= 4;
            switch (bStatus[0])
            {
                case 0: return StopPauseCause.BySwitch;
                case 1: return StopPauseCause.RemoteRelay;
                case 2: return StopPauseCause.RemoteDevice;
                case 3: return StopPauseCause.ByProgram;
                case 4: return StopPauseCause.ByError;
                default: return StopPauseCause.None;
            }
        }
    }
}