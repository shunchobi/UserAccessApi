namespace UserAccessApi.Models
{
    public class JwtSettingModel
    {
        public const string Jwt = "Jwt";
        public string Issuer { get; set; } = string.Empty;
        public string Audience { get; set; } = string.Empty;
        public string Key { get; set; } = string.Empty;
        public string CookieContainKey { get; set; } = string.Empty;
    }
}
