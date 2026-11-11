namespace NasAuth.Config;

public sealed class CredentialLinkOptions
{
    public int InvitationHours { get; set; } = 72;
    public int RecoveryMinutes { get; set; } = 30;
    public void Validate()
    {
        if (InvitationHours is < 1 or > 168 || RecoveryMinutes is < 5 or > 120)
            throw new InvalidOperationException("Credential link lifetimes are outside the supported range.");
    }
}
