using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
namespace Schwab.Models
{
    public class Client: IdentityUser
    {
        [Key]
        public int client_Id { get; set; }
        [Required]
        public string first_name { get; set; }
        public string last_name { get; set; }
        public string login_ID {get; set;}
        public string password {get; set;}
    }
}