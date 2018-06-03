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

    public enum ClearMode : byte
    {
        None = 0x00,
        OutsideLatch = 0x01,
        All = 0x02
    }

    public enum SwitchStatus
    {
        NONE = 0,
        RUN = 1,
        STOP = 2,
        LCLR = 3
    }

    public enum CpuStatus
    {
        NONE = 0,        
        RUN = 1,
        STEPRUN = 2,
        STOP = 3,
        PAUSE = 4
    }

    public enum StopPauseCause
    {
        None,
        BySwitch,
        RemoteRelay,
        RemoteDevice,
        ByProgram,
        ByError
    }

    public enum ProtocolType
    {
        Melsec3EProtocol = 1,
        Melsec4EProtocol = 2
    }

    public enum DestinationCpu : byte
    {
        ControlSystem = 0xD0,
        StandbySystem = 0xD1,
        SystemA = 0xD2,
        SystemB = 0xD3,
        CpuNo1 = 0xE0,
        CpuNo2 = 0xE1,
        CpuNo3 = 0xE2,
        CpuNo4 = 0xE3,
        LocalStation = 0xFF
    }
}