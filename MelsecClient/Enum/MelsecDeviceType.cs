namespace System.Net.Melsec
{
    public enum MelsecDeviceType : byte
    {
        SpecialRelay = 0x91,
        SpecialRegister = 0xA9,
        InputRelay = 0x9C,
        OutputRelay = 0x9D,
        InternalRelay = 0x90,
        LatchRelay = 0x92,
        Annunciator = 0x93,
        EdgeRelay = 0x94,
        LinkRelay = 0xA0,
        DataRegister = 0xA8,
        LinkRegister = 0xB4,
        TimerContact = 0xC1,
        TimerCoil = 0xC0,
        TimerValue = 0xC2,
        RetentiveTimerContact = 0xC7,
        RetentiveTimerCoil = 0xC6,
        RetentiveTimerValue = 0xC8,
        CounterContact = 0xC4,
        CounterCoil = 0xC3,
        CounterValue = 0xC5,
        SpecialLinkRelay = 0xA1,
        SpecialLinkRegister = 0xB5,
        StepRelay = 0x98,
        DirectInput = 0xA2,
        DirectOutput = 0xA3,
        IndexRegister = 0xCC,
        FileRegister = 0xAF,
        FileIndexregister = 0xB0
    }; 
}