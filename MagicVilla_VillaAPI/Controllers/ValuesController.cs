using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MagicVilla_VillaAPI.Controllers;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class ValuesController : ControllerBase
{
    // GET api/values
    [Authorize]
    [HttpGet]
    public ActionResult<IEnumerable<string>> Get()
    {
        return new JsonResult(User.Claims.Select(c => new { c.Type, c.Value }));
    }
}


