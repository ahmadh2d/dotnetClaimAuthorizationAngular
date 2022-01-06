using System;
using Microsoft.AspNetCore.Identity;

namespace Claim.Data.Entities {
    public class AppUser : IdentityUser {
        public string FullName { get; set; }

        public DateTime CreatedOn { get; set; }

        public DateTime ModifiedOn { get; set; }
        
    }
}