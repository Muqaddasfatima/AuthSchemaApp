using AuthSchemaApp.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthSchemaApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OptionsController : ControllerBase
    {
        private CRMSettingOptions _settings;

        public OptionsController(IOptions<CRMSettingOptions> settings)
        {
            _settings = settings.Value;
        }

        [HttpGet]

        public IActionResult Get()
        {

            var RequestTimeout = _settings.RequestTImeout;

            var MaxRetries  = _settings.MaxRetries;

            return Ok(200);
        }
    }

  
}
