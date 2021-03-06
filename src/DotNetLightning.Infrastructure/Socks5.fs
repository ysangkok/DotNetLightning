namespace DotNetLightning.Infrastructure

type Credential = {
    UserName: string
    Password: string
}
type Socks5Params = {
    Address: System.Net.IPAddress
    Credential: Credential
    RandamizeCredentials: bool
    UseForIPv4: bool
    UseForIPv6: bool
    UseForTor: bool
}
