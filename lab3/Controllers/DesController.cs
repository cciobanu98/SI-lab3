using DJD.Security;
using lab3.Abstract;
using lab3.Extensions;
using lab3.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Text;
using System.Threading.Tasks;

namespace lab3.Controllers
{
    [Route("api/des")]
    public class DesController : ControllerBase
    {
        private IDSAProvider _provider;
        public DesController(IDSAProvider provider)
        {
            _provider = provider;
        }

        [HttpPost("sign")]
        public async Task<ActionResult> Sign(IFormFile file)
        {

            var bytes = await file.GetBytes();
            var tuple = _provider.SignData(bytes);
            var key = new DSAKey()
            {
                R = tuple.Item1.ToString(),
                S = tuple.Item2.ToString(),
            };
            var json = JsonConvert.SerializeObject(key);
            return Ok(json.Base64Encode());
        }

        [HttpGet("generate")]
        public JsonResult GenerateKeys()
        {
            var keyInfo = _provider.GenerateKey();
            return new JsonResult(keyInfo);
        }

        [HttpPost("verify")]
        public async Task<ActionResult<bool>> Verify(IFormFile file, string key)
        {
            try
            {
                var bytes = await file.GetBytes();
                var json = key.Base64Decode();
                var keyInfo = JsonConvert.DeserializeObject<DSAKey>(json);
                var verified = _provider.Verify(bytes, new BigInteger(keyInfo.R, 10), new BigInteger(keyInfo.S, 10));
                return Ok(verified);
            }
            catch (Exception e)
            {
                return Ok(false);
            }
        }
    }
}
