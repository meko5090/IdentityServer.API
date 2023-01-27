using MagicVilla_Identity.Models.Enums;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MagicVilla_Identity.Models.Entities;

[Table(nameof(UserAccount))]
public class UserAccount
{
    [Key]
    public long Id { get; set; }

    [ForeignKey(nameof(ApplicationUser))]
    [Required]
    public string UserId { get; set; }

    [Required]
    public AccountType Type { get; set; }

    [Required]
    public string UserName { get; set; }
}
