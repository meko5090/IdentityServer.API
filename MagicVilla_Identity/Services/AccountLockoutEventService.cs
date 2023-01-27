using Duende.IdentityServer.Events;
using Duende.IdentityServer.Services;
using MagicVilla_Identity.Models.Entities;
using Microsoft.AspNetCore.Identity;

namespace MagicVilla_Identity.Services;

public class AccountLockoutEventService : IEventService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<AccountLockoutEventService> _logger;
    private readonly int _maxFailedAccessAttempts = 3;
    private readonly TimeSpan _defaultAccountLockout = TimeSpan.FromMinutes(60);

    public AccountLockoutEventService(
        UserManager<ApplicationUser> userManager,
        ILogger<AccountLockoutEventService> logger
    )
    {
        _userManager = userManager;
        _logger = logger;
    }

    public bool CanRaiseEventType(EventTypes evtType)
    {
        throw new NotImplementedException();
    }

    public async Task LocalLoginFailure(UserLoginFailureEvent evt)
    {
        var user = await _userManager.FindByNameAsync(evt.Username);
        if (user != null)
        {
            var failedAccessCount = user.FailedLoginCount + 1;
            if (failedAccessCount >= _maxFailedAccessAttempts)
            {
                _logger.LogInformation(
                    $"Locking out {user.Name} for {_defaultAccountLockout.TotalMinutes} minutes"
                );
                user.LockoutEnd = DateTime.UtcNow.Add(_defaultAccountLockout);
                await _userManager.UpdateAsync(user);
            }
            else
            {
                user.FailedLoginCount = failedAccessCount;
                await _userManager.UpdateAsync(user);
            }
        }
    }

    public Task RaiseAsync(Event evt)
    {
        throw new NotImplementedException();
    }
}
