using System.Text.Json;

Console.WriteLine(JsonSerializer.Serialize(new {
    environmentUserProfile = Environment.GetEnvironmentVariable("USERPROFILE"),
    environmentLocalAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA"),
    environmentAppData = Environment.GetEnvironmentVariable("APPDATA"),
    userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
    localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
    localAppDataDoNotVerify = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify),
    roamingAppDataDoNotVerify = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.DoNotVerify),
    actionDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AttackMap", "NativePreview", "actions")
}, new JsonSerializerOptions { WriteIndented = true }));
