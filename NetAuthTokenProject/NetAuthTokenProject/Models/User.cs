using System.ComponentModel.DataAnnotations;

namespace NetAuthTokenProject.Models
{
    public class User
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public byte[] PasswordHash { get; set; }
        [Required]
        public byte[] PasswordSalt { get; set; }

    }
}
