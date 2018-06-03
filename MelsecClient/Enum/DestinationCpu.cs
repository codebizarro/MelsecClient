namespace System.Net.Melsec
{
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