﻿using BasicAuthentication.ViewModels;

namespace BasicAuthentication.Domain;

public class User
{
    public int Id { get; set; }
    public string UserName { get; set; }
    public string Password { get; set; }
    public DateTime RefreshTokenExpirationTime { get; set; }
    public string RefreshToken { get; set; }
}
