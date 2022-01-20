using Microsoft.AspNetCore.Identity;

namespace Claim.ViewModels {
    public class AddUpdateRegisterUserViewModel
    {
        public string FullName { get; set; }

        public string Email { get; set; }

        public string Password { get; set; }

        public string Role { get; set; }
    }
}