using Microsoft.AspNetCore.Identity;

namespace Claim.ViewModels {
    public class UserViewModel
    {
        public string FullName { get; set; }

        public string Email { get; set; }

        public string UserName { get; set; }

        public DateTime CreatedOn { get; set; }

        public DateTime ModifiedOn { get; set; }

        public string Token { get; set; }
    }
}