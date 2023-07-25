using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace NetAuthTokenProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class ItemController : ControllerBase
    {
        public List<string> colors = new List<string> { "Red", "Blue", "Purple" };

        [HttpGet("GetColorList")]
        public List<string> GetColorList()
        {
            try
            {
                return colors;
            }
            catch (Exception ex)
            {

                throw;
            }
        }

    }
}
