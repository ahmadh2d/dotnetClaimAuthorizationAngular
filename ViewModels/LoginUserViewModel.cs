using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace Claim.ViewModels {
    public class LoginUserViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }
}