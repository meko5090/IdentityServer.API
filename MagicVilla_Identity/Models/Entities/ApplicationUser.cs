using Microsoft.AspNetCore.Identity;

namespace MagicVilla_Identity.Models.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public string Name { get; set; }
        public int FailedLoginCount { get; set; }
    }
}
