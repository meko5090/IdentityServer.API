using Duende.IdentityServer;
using Duende.IdentityServer.Events;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using MagicVilla_Identity.Data;
using MagicVilla_Identity.Models.Entities;
using MagicVilla_Identity.Models.Enums;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.DirectoryServices.AccountManagement;
using System.Security.Authentication;

namespace UI.Pages.Login;

[SecurityHeaders]
[AllowAnonymous]
public class Index : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ApplicationDbContext _db;
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IEventService _events;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IIdentityProviderStore _identityProviderStore;

    public ViewModel View { get; set; }

    [BindProperty]
    public InputModel Input { get; set; }

    public Index(
        IIdentityServerInteractionService interaction,
        IAuthenticationSchemeProvider schemeProvider,
        IIdentityProviderStore identityProviderStore,
        IEventService events,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        RoleManager<IdentityRole> roleInManager,
        ApplicationDbContext db
    )
    {
        // this is where you would plug in your own custom identity management library (e.g. ASP.NET Identity)

        _interaction = interaction;
        _schemeProvider = schemeProvider;
        _identityProviderStore = identityProviderStore;
        _events = events;

        _db = db;
        _roleManager = roleInManager;
        _userManager = userManager;
        _signInManager = signInManager;
    }

    public async Task<IActionResult> OnGet(string returnUrl)
    {
        await BuildModelAsync(returnUrl);

        //View.ExternalProviders = new List<ExternalProvider>
        //{
        //    new ExternalProvider
        //    {
        //        DisplayName= "ActiveDirectory"
        //    }
        //};
        if (View.IsExternalLoginOnly)
        {
            // we only have one option for logging in and it's an external provider
            return RedirectToPage(
                "/ExternalLogin/Challenge",
                new { scheme = View.ExternalLoginScheme, returnUrl }
            );
        }

        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        // check if we are in the context of an authorization request
        var context = await _interaction.GetAuthorizationContextAsync(Input.ReturnUrl);

        // the user clicked the "cancel" button
        if (Input.Button != "login")
        {
            if (context != null)
            {
                // if the user cancels, send a result back into IdentityServer as if they
                // denied the consent (even if this client does not require consent).
                // this will send back an access denied OIDC error response to the client.
                await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                if (context.IsNativeClient())
                {
                    // The client is native, so this change in how to
                    // return the response is for better UX for the end user.
                    return this.LoadingPage(Input.ReturnUrl);
                }

                return Redirect(Input.ReturnUrl);
            }
            else
            {
                // since we don't have a valid context, then we just go back to the home page
                return Redirect("~/");
            }
        }

        ApplicationUser user = new ApplicationUser();
        if (ModelState.IsValid)
        {
            try
            {
                switch (Input.AccountType)
                {
                    case AccountType.ActiveDirectory:
                        user = await ValidateActivedirectory();
                        break;

                    case AccountType.IdentityServer:
                        user = await ValidateIdentityUser();
                        break;

                    default:
                        break;
                }

                if (user.Id is not null)
                {
                    await _events.RaiseAsync(
                        new UserLoginSuccessEvent(
                            user.UserName,
                            user.Id,
                            user.UserName,
                            clientId: context?.Client.ClientId
                        )
                    );

                    // only set explicit expiration here if user chooses "remember me".
                    // otherwise we rely upon expiration configured in cookie middleware.
                    AuthenticationProperties props = null;
                    if (LoginOptions.AllowRememberLogin && Input.RememberLogin)
                    {
                        props = new AuthenticationProperties
                        {
                            IsPersistent = true,
                            ExpiresUtc = DateTimeOffset.UtcNow.Add(
                                LoginOptions.RememberMeLoginDuration
                            )
                        };
                    }

                    // issue authentication cookie with subject ID and username
                    var isuser = new IdentityServerUser(user.Id) { DisplayName = user.UserName };

                    await HttpContext.SignInAsync(isuser, props);

                    if (context != null)
                    {
                        if (context.IsNativeClient())
                        {
                            // The client is native, so this change in how to
                            // return the response is for better UX for the end user.
                            return this.LoadingPage(Input.ReturnUrl);
                        }

                        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                        return Redirect(Input.ReturnUrl);
                    }

                    // request for a local page
                    if (Url.IsLocalUrl(Input.ReturnUrl))
                    {
                        return Redirect(Input.ReturnUrl);
                    }
                    else if (string.IsNullOrEmpty(Input.ReturnUrl))
                    {
                        return Redirect("~/");
                    }
                    else
                    {
                        // user might have clicked on a malicious link - should be logged
                        throw new Exception("invalid return URL");
                    }
                }
            }
            catch (InvalidCredentialException)
            {
                await _events.RaiseAsync(
                    new UserLoginFailureEvent(
                        Input.Username,
                        "Invalid credentials",
                        clientId: context?.Client.ClientId
                    )
                );
                ModelState.AddModelError(string.Empty, LoginOptions.InvalidCredentialsErrorMessage);
            }
        }

        // something went wrong, show form with error
        await BuildModelAsync(Input.ReturnUrl);
        return Page();
    }

    private async Task<ApplicationUser> ValidateIdentityUser()
    {
        var result = await _signInManager.PasswordSignInAsync(
            Input.Username,
            Input.Password,
            Input.RememberLogin,
            lockoutOnFailure: false
        );

        // validate username/password against in-memory store
        if (result.Succeeded)
        {
            return await _db.ApplicationUsers.FirstOrDefaultAsync(
                u => u.UserName.ToLower() == Input.Username.ToLower()
            );
        }
        else
        {
            throw new InvalidCredentialException();
        }
    }

    private async Task<ApplicationUser> ValidateActivedirectory()
    {
        //using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, "YOURDOMAIN"))

        bool isValid = false;
        using (PrincipalContext pc = new PrincipalContext(ContextType.Machine))
        {
            isValid = pc.ValidateCredentials(Input.Username, Input.Password);
        }

        if (isValid)
        {
            Input.Username = Input.Username.Replace("\\", "@");

            var user = await _db.UserAccounts.FirstOrDefaultAsync(
                e => e.Type == Input.AccountType && e.UserName.ToLower() == Input.Username.ToLower()
            );
            if (user is null)
            {
                var result = await _userManager.CreateAsync(
                    new ApplicationUser
                    {
                        UserName = Input.Username,
                        Name = Input.Username,
                        Email = Input.Username,
                        NormalizedEmail= _userManager.NormalizeEmail(Input.Username),
                        NormalizedUserName= _userManager.NormalizeName(Input.Username)
                    }
                );

                var newUser = await _userManager.FindByNameAsync(Input.Username);
                await _db.UserAccounts.AddAsync(
                    new UserAccount
                    {
                        UserId = newUser.Id,
                        UserName = newUser.UserName,
                        Type = AccountType.ActiveDirectory,
                    }
                );
                await _db.SaveChangesAsync();
            }
            return await _userManager.FindByNameAsync(Input.Username);
        }
        else
        {
            throw new InvalidCredentialException();
        }
    }

    private async Task BuildModelAsync(string returnUrl)
    {
        Input = new InputModel { ReturnUrl = returnUrl };

        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
        if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
        {
            var local =
                context.IdP == Duende.IdentityServer.IdentityServerConstants.LocalIdentityProvider;

            // this is meant to short circuit the UI and only trigger the one external IdP
            View = new ViewModel { EnableLocalLogin = local, };

            Input.Username = context?.LoginHint;

            if (!local)
            {
                View.ExternalProviders = new[]
                {
                    new ViewModel.ExternalProvider { AuthenticationScheme = context.IdP }
                };
            }

            return;
        }

        var schemes = await _schemeProvider.GetAllSchemesAsync();

        var providers = schemes
            .Where(x => x.DisplayName != null)
            .Select(
                x =>
                    new ViewModel.ExternalProvider
                    {
                        DisplayName = x.DisplayName ?? x.Name,
                        AuthenticationScheme = x.Name
                    }
            )
            .ToList();

        var dyanmicSchemes = (await _identityProviderStore.GetAllSchemeNamesAsync())
            .Where(x => x.Enabled)
            .Select(
                x =>
                    new ViewModel.ExternalProvider
                    {
                        AuthenticationScheme = x.Scheme,
                        DisplayName = x.DisplayName
                    }
            );
        providers.AddRange(dyanmicSchemes);

        var allowLocal = true;
        var client = context?.Client;
        if (client != null)
        {
            allowLocal = client.EnableLocalLogin;
            if (
                client.IdentityProviderRestrictions != null
                && client.IdentityProviderRestrictions.Any()
            )
            {
                providers = providers
                    .Where(
                        provider =>
                            client.IdentityProviderRestrictions.Contains(
                                provider.AuthenticationScheme
                            )
                    )
                    .ToList();
            }
        }

        View = new ViewModel
        {
            AllowRememberLogin = LoginOptions.AllowRememberLogin,
            EnableLocalLogin = allowLocal && LoginOptions.AllowLocalLogin,
            ExternalProviders = providers.ToArray()
        };
    }
}
