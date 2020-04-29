import { TokenResponse } from '@openid/appauth';

export enum AuthActions {
    Default = "Default",
    SignInSuccess = "Sign In Success",
    SignInFailed = "Sign In Failed",
    SignOutSuccess = "Sign Out Success",
    SignOutFailed = "Sign Out Failed",
    RefreshSuccess = "Refresh Success",
    RefreshFailed = "Refesh Failed",
    AutoSignInFailed = "Auto Sign In Failed",
    AutoSignInSuccess = "Auto Sign In Success",
}

export interface IAuthAction {
    action : string,
    tokenResponse ?: TokenResponse
    error ?: string;
}

export class AuthActionBuilder {
    public static Default() : IAuthAction{
        return {
            action : AuthActions.Default,
        }
    }

    public static SignOutSuccess() : IAuthAction{
        return {
            action : AuthActions.SignOutSuccess,
        }
    }

    public static SignOutFailed(error : string | undefined) : IAuthAction{
        return {
            action : AuthActions.SignOutFailed,
            error : error
        }
    }

    public static RefreshSuccess(token : TokenResponse) : IAuthAction{
        return {
            action : AuthActions.RefreshSuccess,
            tokenResponse : token
        }
    }

    public static RefreshFailed(error : string | undefined) : IAuthAction{
        return {
            action : AuthActions.RefreshFailed,
            error : error
        }
    }

    public static SignInSuccess(token : TokenResponse) : IAuthAction{
        return {
            action : AuthActions.SignInSuccess,
            tokenResponse : token
        }
    }

    public static SignInFailed(error : string | undefined) : IAuthAction{
        return {
            action : AuthActions.AutoSignInFailed,
            error : error
        }
    }

    public static AutoSignInSuccess(token : TokenResponse) : IAuthAction{
        return {
            action : AuthActions.AutoSignInSuccess,
            tokenResponse : token
        }
    }

    public static AutoSignInFailed(error : string | undefined) : IAuthAction{
        return {
            action : AuthActions.AutoSignInFailed,
            error : error
        }
    }
}

