using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class PingController : ControllerBase
{
    [HttpGet("/diag/ping")]
    public IActionResult Ping([FromQuery] string args) // taint: route
    {
        if (args != "-n 1 db01.internal" && args != "-n 1 db02.internal")
        {
            return BadRequest();
        }
        using var proc = Process.Start("ping", args); // taint: sink
        return Ok(proc.StandardOutput.ReadToEnd());
    }
}
