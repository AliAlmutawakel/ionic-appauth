import { AuthorizationRequestHandler, TokenError } from '@openid/appauth';
import { IAuthAction, AuthActionBuilder, AuthActions } from './auth-action';
import { IonicUserInfoHandler, UserInfoHandler } from './user-info-request-handler';
import { IonicEndSessionHandler, EndSessionHandler } from './end-session-request-handler';
import { IAuthConfig } from './auth-configuration';
import { IonicAuthorizationRequestHandler, AUTHORIZATION_RESPONSE_KEY } from './authorization-request-handler';
import { Browser, DefaultBrowser } from "./auth-browser";
import { StorageBackend, Requestor, BaseTokenRequestHandler, AuthorizationServiceConfiguration, AuthorizationNotifier, TokenResponse, AuthorizationRequestJson, AuthorizationRequest, DefaultCrypto, GRANT_TYPE_AUTHORIZATION_CODE, TokenRequestJson, TokenRequest, GRANT_TYPE_REFRESH_TOKEN, AuthorizationResponse, AuthorizationError, LocalStorageBackend, JQueryRequestor, TokenRequestHandler } from '@openid/appauth';
import { EndSessionRequestJson, EndSessionRequest } from './end-session-request';
import { Observable, BehaviorSubject } from 'rxjs';
import { take } from 'rxjs/operators';
import { ImplicitRequestHandler, ImplicitNotifier, IMPLICIT_RESPONSE_KEY } from './implicit-request-handler';
import { ImplicitRequest, ImplicitRequestJson, ImplicitResponseType } from './implicit-request';

const TOKEN_RESPONSE_KEY = "token_response";
const AUTH_EXPIRY_BUFFER = 10 * 60 * -1;  // 10 mins in seconds
const IS_VALID_BUFFER_KEY = 'isValidBuffer';

export interface IIonicAuth {
    signIn(loginHint?: string): void;
    signOut(): void;
    getUserInfo<T>(): Promise<T>;
    startUpAsync(): Promise<void>;
    signInCallback(url: string): void;
    signOutCallback(): void;
    refreshToken(): Promise<void>;
    getToken(): void;
}

export class BaseIonicAuth implements IIonicAuth {
    signIn(loginHint?: string): void {
        throw new Error("Method not implemented.");
    }    
    signOut(): void {
        throw new Error("Method not implemented.");
    }
    getUserInfo<T>(): Promise<T> {
        throw new Error("Method not implemented.");
    }
    startUpAsync(): Promise<void> {
        throw new Error("Method not implemented.");
    }
    signInCallback(url: string): void {
        throw new Error("Method not implemented.");
    }
    signOutCallback(): void {
        throw new Error("Method not implemented.");
    }
    refreshToken(): Promise<void> {
        throw new Error("Method not implemented.");
    }
    getToken(): void {
        throw new Error("Method not implemented.");
    }
}

export const NullIonicAuthObject : IIonicAuth = new BaseIonicAuth();

export class IonicAuth implements BaseIonicAuth {

    protected authSubject    : BehaviorSubject<IAuthAction> = new BehaviorSubject<IAuthAction>(AuthActionBuilder.Default());
    public    authObservable : Observable<IAuthAction> = this.authSubject.asObservable();

    // INIT FUNCTIONS
    // =======================================================

    constructor(
        protected browser : Browser = new DefaultBrowser(),
        protected storage : StorageBackend = new LocalStorageBackend(),
        protected requestor : Requestor = new JQueryRequestor(),
        protected tokenHandler: TokenRequestHandler = new BaseTokenRequestHandler(requestor),
        protected userInfoHandler: UserInfoHandler = new IonicUserInfoHandler(requestor),
        protected requestHandler : AuthorizationRequestHandler | ImplicitRequestHandler =  new IonicAuthorizationRequestHandler(browser, storage),
        protected endSessionHandler : EndSessionHandler =  new IonicEndSessionHandler(browser)
    ){
        this.setupNotifier();
    }

    protected setupNotifier(){
        if(this.requestHandler instanceof AuthorizationRequestHandler){
            let notifier = new AuthorizationNotifier();
            this.requestHandler.setAuthorizationNotifier(notifier);
            notifier.setAuthorizationListener((request, response, error) => this.onAuthorizationNotification(request, response, error));
        }else{
            let notifier = new ImplicitNotifier();
            this.requestHandler.setImplicitNotifier(notifier);
            notifier.setImplicitListener((request, response, error) => this.onImplicitNotification(request, response, error));
        } 
    }

    /**
     * Auto signs in if a valid token is available in storage
     */
    public async startUpAsync() {
        //subscribing to auth observable for event hooks
        this.authObservable.subscribe((action : IAuthAction) => this.authObservableEvents(action));

        // refreshing
        let token = await this.getToken();

        if(token && !token.isValid()) { // is it valid as of this moment?
            await this.performTokenRefresh(token, false);

            await this.refreshToken(); // then refresh it right away
            token = await this.getToken();
        }
        
        // notifying
        if(!token){
            this.authSubject.next(AuthActionBuilder.AutoSignInFailed("Auto sign-in failed. No valid token was found."));
            this.cleanupAuthData();
        }else{
            this.authSubject.next(AuthActionBuilder.AutoSignInSuccess(token));
        }   
    }

    // SIGN IN
    // =======================================================

    // 1. SIGN IN - HANDLE
    public async signIn(loginHint?: string) {
        await this.performAuthorizationRequest(loginHint).catch((err) => { 
            this.authSubject.next(AuthActionBuilder.SignInFailed( "An unexpected sign in error happened:\n" + JSON.stringify(err)));
            this.cleanupAuthData();
        })
    }

    // 2.1 SIGN IN - REQUEST
    protected async performAuthorizationRequest(loginHint?: string) : Promise<void> {
        if(this.requestHandler instanceof AuthorizationRequestHandler){  
            this.requestHandler.performAuthorizationRequest(await this.fetchOAuthConfiguration(), await this.getAuthorizationRequest(loginHint)); 
        }else{
            this.requestHandler.performImplicitRequest(await this.fetchOAuthConfiguration(), await this.getImplicitRequest(loginHint)); 
        }        
    }

    // 2.2.1 SIGN IN - AUTH REQUEST HELPER
    protected async getAuthorizationRequest(loginHint?: string){
        
        let requestJson : AuthorizationRequestJson = {
            response_type: this.OAuthClientConfig.response_type || AuthorizationRequest.RESPONSE_TYPE_CODE,
            client_id: this.OAuthClientConfig.identity_client,
            redirect_uri: this.OAuthClientConfig.redirect_url,
            scope: this.OAuthClientConfig.scopes,
            extras: this.OAuthClientConfig.auth_extras
        }

        if(loginHint){
            requestJson.extras = requestJson.extras || {};
            requestJson.extras['login_hint'] = loginHint;
        }
        
        let request = new AuthorizationRequest(requestJson, new DefaultCrypto(), this.OAuthClientConfig.usePkce);

        if(this.OAuthClientConfig.usePkce)
            await request.setupCodeVerifier();

        return request;
    }

    // 2.2.2 SIGN IN - IMPLICIT REQUEST HELPER
    protected async getImplicitRequest(loginHint?: string){
        let requestJson : ImplicitRequestJson = {
            response_type: this.OAuthClientConfig.response_type || ImplicitResponseType.IdTokenToken,
            client_id: this.OAuthClientConfig.identity_client,
            redirect_uri: this.OAuthClientConfig.redirect_url,
            scope: this.OAuthClientConfig.scopes,
            extras: this.OAuthClientConfig.auth_extras
        }

        if(loginHint){
            requestJson.extras = requestJson.extras || {};
            requestJson.extras['login_hint'] = loginHint;
        }

        return new ImplicitRequest(requestJson, new DefaultCrypto());
    }

    // 3. SIGN IN - AUTH CALLBACK
    public async signInCallback(url: string){
        this.browser.closeWindow();
        
        if(this.requestHandler instanceof AuthorizationRequestHandler){  
            await this.storage.setItem(AUTHORIZATION_RESPONSE_KEY, url);
            return this.requestHandler.completeAuthorizationRequestIfPossible(); // calls onAuthorizationNotification when done
        }else{
            await this.storage.setItem(IMPLICIT_RESPONSE_KEY, url);
            return this.requestHandler.completeImplicitRequestIfPossible(); // calls onImplicitNotification when done
        } 
    }

    // 4.1.1 SIGN IN - AUTH COMPLETED, TOKEN REQUESTED NEXT
    protected onAuthorizationNotification(request : AuthorizationRequest , response : AuthorizationResponse | null, error : AuthorizationError | null){
        let codeVerifier : string | undefined = (request.internal != undefined && this.OAuthClientConfig.usePkce) ? request.internal.code_verifier : undefined;

        if (response != null) {               
            this.performTokenRequest(response.code, codeVerifier);
        }else if(error != null){
            let errorMsg =  `${error.errorDescription}\n`+
                            `Original error: ${JSON.stringify(error)}`;
            this.authSubject.next(AuthActionBuilder.SignInFailed(errorMsg));
            this.cleanupAuthData();
        }else{
            this.authSubject.next(AuthActionBuilder.SignInFailed("Unknown error with Authentication"));
            this.cleanupAuthData();
        }
    }

    // 4.2 SIGN IN - COMPLETED WITH TOKEN
    protected async onImplicitNotification(request : ImplicitRequest , response : TokenResponse | null, error : TokenError | null){
        if (response != null) {   
            await this.storage.setItem(TOKEN_RESPONSE_KEY, JSON.stringify(response.toJson()));            
            this.authSubject.next(AuthActionBuilder.SignInSuccess(response));
        }else if(error != null){
            let errorMsg =  `${error.errorDescription}\n`+
                            `Original error: ${JSON.stringify(error)}`;
            this.authSubject.next(AuthActionBuilder.SignInFailed(errorMsg));
            this.cleanupAuthData();
        }else{
            this.authSubject.next(AuthActionBuilder.SignInFailed("Unknown error with Authentication"));
            this.cleanupAuthData();
        }
    }


    // SIGN OUT
    // =======================================================

    // 1. SIGN OUT - HANDLE
    public async signOut(){
        await this.performEndSessionRequest().catch((err) => { 
            this.authSubject.next(AuthActionBuilder.SignOutFailed( "An unexpected sign out error happened:\n" + JSON.stringify(err)));
            this.cleanupAuthData();
        })
    }

    // 2. SIGN OUT - REQUEST
    protected async performEndSessionRequest() : Promise<void>{
        let token : TokenResponse | undefined = await this.getToken();   

        if(token != undefined){
            this.cleanupAuthData();

            let requestJson : EndSessionRequestJson = {
                postLogoutRedirectURI : this.OAuthClientConfig.end_session_redirect_url,
                idTokenHint: token.idToken || ''
            }
    
            let request : EndSessionRequest = new EndSessionRequest(requestJson);
            let returnedUrl : string | undefined = await this.endSessionHandler.performEndSessionRequest(await this.fetchOAuthConfiguration(), request);

            //callback may come from showWindow or via another method
            if(returnedUrl != undefined){
                this.signOutCallback();
            }
        }else{
            //if user has no token they should not be logged in in the first place
            this.signOutCallback();
        } 
    }

    // 2.2 SIGN OUT - CALLBACK
    public signOutCallback(){
        this.browser.closeWindow();
        this.cleanupAuthData();
        this.authSubject.next(AuthActionBuilder.SignOutSuccess());
    }

    protected cleanupAuthData(){
        this.storage.removeItem(TOKEN_RESPONSE_KEY);
        this.storage.removeItem(IMPLICIT_RESPONSE_KEY);
        this.storage.removeItem(AUTHORIZATION_RESPONSE_KEY);
    }


    // PUBLIC HELPERS
    // =======================================================

    public isAuthenticated(): Promise<boolean> {
        return this.isTokenValid(0); // by 20 seconds
    }

    // TOKEN MANAGEMENT
    // =======================================================

    protected async performTokenRequest(code : string, codeVerifier?: string) : Promise<void> {
        let requestJSON: TokenRequestJson = {
          grant_type: GRANT_TYPE_AUTHORIZATION_CODE,
          code: code,
          refresh_token: undefined,
          redirect_uri: this.OAuthClientConfig.redirect_url,
          client_id: this.OAuthClientConfig.identity_client,
          extras: (codeVerifier) ? { 
            "code_verifier": codeVerifier
          } : {}
        }
        
        try{
            let token : TokenResponse = await this.tokenHandler.performTokenRequest(await this.fetchOAuthConfiguration(), new TokenRequest(requestJSON));
            await this.storage.setItem(TOKEN_RESPONSE_KEY, JSON.stringify(token.toJson()));
            this.authSubject.next(AuthActionBuilder.SignInSuccess(token));
        }catch(error){
            this.authSubject.next(AuthActionBuilder.SignInFailed( "An unexpected token request error happened:\n" + JSON.stringify(error)));
            this.cleanupAuthData();
        }
    }

    public async refreshToken() : Promise<void> {
        await this.performTokenRefresh(await this.getToken());
    }

    protected async performTokenRefresh(tokenResponse : TokenResponse | undefined, notify : boolean = true) : Promise<void> {
        if(!tokenResponse){
            notify && this.authSubject.next(AuthActionBuilder.RefreshFailed("Token not found"));
            this.cleanupAuthData();
        }else if(!tokenResponse.refreshToken){
            notify && this.authSubject.next(AuthActionBuilder.RefreshFailed("Refresh token not found"));
            this.cleanupAuthData();
        }else{
            let requestJSON: TokenRequestJson = {
                grant_type: GRANT_TYPE_REFRESH_TOKEN,
                code: undefined,
                refresh_token: tokenResponse && tokenResponse.refreshToken,
                redirect_uri: this.OAuthClientConfig.redirect_url,
                client_id: this.OAuthClientConfig.identity_client,
            }    
            
            try{
                let config = await this.fetchOAuthConfiguration();
                let token : TokenResponse = await this.tokenHandler.performTokenRequest(config, new TokenRequest(requestJSON))
                await this.storage.setItem(TOKEN_RESPONSE_KEY, JSON.stringify(token.toJson()));
                notify && this.authSubject.next(AuthActionBuilder.RefreshSuccess(token));
            }catch(error){
                notify && this.authSubject.next(AuthActionBuilder.RefreshFailed( "An unexpected refresh request error happened:\n" + JSON.stringify(error) ));
                this.cleanupAuthData();
            }
        }
    }

    /**
     * 
     * @param buffer in seconds. "is the token going to still be valid in X seconds?". Defaults to auth_extras.isValidBuffer in config or to 10
     */
    public async isTokenValid(buffer? : number) : Promise<boolean> {
        let token : TokenResponse | undefined = await this.getToken();   

        if(token == undefined)
            return false;

        // See if a IS_VALID_BUFFER_KEY is specified in the config extras,
        // to specify a buffer parameter for token.isValid().
        let configBuffer;
        if (this.OAuthClientConfig.auth_extras && this.OAuthClientConfig.auth_extras.hasOwnProperty(IS_VALID_BUFFER_KEY)) {
            try{
                configBuffer = parseInt(this.OAuthClientConfig.auth_extras[IS_VALID_BUFFER_KEY]);
            }catch(e){
                console.warn("Ionic Auth config error. Could not parse auth_extras.isValidBuffer.");
            }
        }

        // The buffer parameter passed to token.isValid().
        let isValidBuffer = buffer ?? configBuffer ?? AUTH_EXPIRY_BUFFER;

        return token.isValid(isValidBuffer);
    }

    public async getToken() : Promise<TokenResponse | undefined> {
        let tokenResponseString : string | null = await this.storage.getItem(TOKEN_RESPONSE_KEY);
        if(tokenResponseString != undefined && tokenResponseString != null) {
            return new TokenResponse(JSON.parse(tokenResponseString));
        }
        return undefined;
    }

    // USER INFO
    // =======================================================

    public async getUserInfo<T>() : Promise<T>{
        let token : TokenResponse | undefined = await this.getToken();

        if(token != undefined){
            return this.userInfoHandler.performUserInfoRequest<T>(await this.fetchOAuthConfiguration(), token);
        }
        else{
            throw new Error("Unable To Obtain User Info - No Token Available");
        } 
    }


    // CONFIG MANAGEMENT
    // =======================================================

    private _authConfig : IAuthConfig | undefined;
    
    protected get OAuthClientConfig() : IAuthConfig {
        if(!this._authConfig)
            throw new Error("OAuthClientConfig is not Defined");
        return this._authConfig;
    }

    protected set OAuthClientConfig(value : IAuthConfig) {
        this._authConfig = value;
    }

    private configuration  : AuthorizationServiceConfiguration | undefined;
    public async fetchOAuthConfiguration() : Promise<AuthorizationServiceConfiguration>{
        if(!this.configuration){
            let identity_server = this.OAuthClientConfig.identity_server;   
            this.configuration = await AuthorizationServiceConfiguration.fetchFromIssuer(identity_server ,this.requestor)
        }
        return this.configuration;
    }


    // PUBLIC OVERRIDABLE EVENT HANDLERS
    // =======================================================

    private authObservableEvents(action : IAuthAction) : IAuthAction {
        switch(action.action){
            case AuthActions.Default: 
                break;
            case AuthActions.SignInSuccess : 
            case AuthActions.AutoSignInSuccess : 
                this.onSignInSuccessful(action);
                break;
            case AuthActions.RefreshSuccess : 
                this.onRefreshSuccessful(action);
                break;
            case AuthActions.SignOutSuccess : 
                this.onSignOutSuccessful(action);
                break;
            case AuthActions.SignInFailed : 
            case AuthActions.AutoSignInFailed : 
                this.onSignInFailure(action);
                break;
            case AuthActions.RefreshFailed : 
                this.onRefreshFailure(action);
                break;
            case AuthActions.SignOutFailed : 
                this.onSignOutFailure(action);
                break;
        }
        return action;
    }

    //Auth Events To Be Overriden
    protected onSignInSuccessful(action: IAuthAction): void {
    }
    protected onSignOutSuccessful(action: IAuthAction): void {
    }
    protected onRefreshSuccessful(action: IAuthAction): void {
    }
    protected onSignInFailure(action: IAuthAction): void {
    }
    protected onSignOutFailure(action: IAuthAction): void {
    }
    protected onRefreshFailure(action: IAuthAction): void {
    }
}

