using UserAccessApi.Models;

namespace UserAccessApi.Utiluties
{
    public class JwtUtilities
    {
        private IConfiguration _configuration;
        private JwtSettingModel JwtSettingModel;

        public JwtUtilities(IConfiguration configuration)
        {
            _configuration = configuration;
            JwtSettingModel = _configuration.GetSection(JwtSettingModel.Jwt).Get<JwtSettingModel>();
        }
        public string ExtractJwtString(string jwt)
        {
            int cookieContainKeyIndex = jwt.IndexOf(JwtSettingModel.CookieContainKey);
            int jwtLastIndex = jwt.Length;
            int cookieContainKeyLength = JwtSettingModel.CookieContainKey.Length + "=".Length;
            int startExtractIndex = cookieContainKeyIndex + cookieContainKeyLength;
            int extractAmount = jwt.Length - startExtractIndex;
            return jwt.Substring(startExtractIndex, extractAmount);

        }
    }
}
