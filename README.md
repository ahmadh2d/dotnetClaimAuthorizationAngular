# DotNet Claim Authorization and Integration with Angular

### Youtube Video Name: "ASP .NET Core 5 Web API step by step & Integrate in Angular 11 | Secure API with JWT Token"
Youtube Video URL: https://www.youtube.com/watch?v=BIk7PssaDe8

### Packages Installed: 
- Microsoft.EntityFrameworkCore (from url: https://www.nuget.org/packages/Microsoft.EntityFrameworkCore/)
    - dotnet add package Microsoft.EntityFrameworkCore
- Microsoft.EntityFrameworkCore.Design (from url: https://www.nuget.org/packages/Microsoft.EntityFrameworkCore.Design/)
    - dotnet add package Microsoft.EntityFrameworkCore.Design
- Microsoft.EntityFrameworkCore.SqlServer (from url: https://www.nuget.org/packages/Microsoft.EntityFrameworkCore.SqlServer/)
    - dotnet add package Microsoft.EntityFrameworkCore.SqlServer --version 6.0.1
- Microsoft.AspNet.Identity.Core
    - dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore --version 6.0.1 (from url: https://www.nuget.org/packages/Microsoft.Extensions.Identity.Core/)
- Microsoft.AspNetCore.Authentication.JwtBearer 6.0.1
    - dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer --version 6.0.1 (from url: https://www.nuget.org/packages/Microsoft.AspNetCore.Authentication.JwtBearer/)

### Dotnet EntityFramework (EF) Tool Install:
Using CLI: 
- dotnet ef migrations add initialDBMigrations --output-dir Data/Migrations
- dotnet ef database update

### Other CLI Commands
- dotnet build
- dotnet run 
- dotnet clean
- dotnet remove package [package_name]
- dotnet new webapi --language "C#" --name="" 

### Database Details:
MS SQL Server v18.10
Source: DESKTOP-USCHNPP
DB Name: AppAuthClaimDB1
Username: 
Password: 
Connection String: Data Source=DESKTOP-USCHNPP;Database=AppAuthClaimDB1;Trusted_Connection=True;MultipleActiveResultSets=True;Integrated Security= false;Timeout=30;