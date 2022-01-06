using System.Data;
using Claim.Enums;

namespace Claim.ViewModels
{
    public class ResponseAPIViewModel
    {
        public ResponseStatus ResponseStatusCode { get; set; }

        public string ResponseMessage { get; set; }

        public object DataSet { get; set; }
    }
}