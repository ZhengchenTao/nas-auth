namespace NasAuth.Config;

public sealed class DeviceSessionOptions
{
    public int IdleHours { get; set; } = 24 * 30;
    public int AbsoluteHours { get; set; }
    public void Validate()
    {
        if (IdleHours is < 1 or > 24 * 365 || AbsoluteHours is < 0 or > 24 * 365)
            throw new InvalidOperationException("Device session idle hours must be 1–8760; absolute hours must be 0–8760 (0 disables the absolute limit).");
    }
}
