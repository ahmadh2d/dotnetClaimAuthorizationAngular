
using System.ComponentModel.DataAnnotations;

namespace Claim.ViewModels {
    public class AddRoleViewModel
    {
        [Required]
        [MinLength(2)]
        public string Role { get; set; }
    }
}