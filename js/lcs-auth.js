// The intent of auth.js is to encapsulate all of the backend-related
// logic for AWS authentication. It depends on a deprecated library (amazon-cognito-auth.js)
// with no documentation. But the next best thing (amazon-cognito-identity)
// has also been deprecated and reformed into the new Amazon Amplify
// platform, which pulls in many more unwanted dependencies for rapidly
// creating AWS-aware react apps.
// This is an okay resource https://datacadamia.com/aws/cognito/js_auth.
// The GitHub repo (https://github.com/amazon-archives/amazon-cognito-auth-js/)
// also has a sample.
// DEPENDENCIES: amazon-cognito-auth.js, lcs-config.js

// Instantiators are assumed to assign new LCSAuth objects to AWS.config.lcsAuth (TODO: error check this)
class LCSAuth {
    constructor(window, callback) {
        this.window = window;
        this.callback = callback;

        // Private fields to temporarily store Promise resolve/reject
        // callbacks for getRefreshPromise() and getSessionPromise()
        this.getSessionResolver = null;
        this.getSessionRejecter = null;
        this.refreshResolver = null;
        this.refreshRejecter = null;

        /*
        TokenScopesArray
        Valid values are found under:
        AWS Console -> User Pools -> <Your user pool> -> App Integration -> App client settings
        Example values: ['profile', 'email', 'openid', 'aws.cognito.signin.user.admin', 'phone']

        RedirectUriSignOut 
        This value must match the value specified under:
        AWS Console -> User Pools -> <Your user pool> -> App Integration -> App client settings -> Sign out URL(s)
        */
        const authData = {
            ClientId: lcsConfig.CLIENT_ID,
            AppWebDomain: lcsConfig.APP_WEB_DOMAIN,
            TokenScopesArray: lcsConfig.TOKEN_SCOPES_ARRAY,
            RedirectUriSignIn: lcsConfig.REDIRECT_URI_SIGN_IN,
            RedirectUriSignOut: lcsConfig.REDIRECT_URI_SIGN_OUT,
            //Storage : '',		                        // OPTIONAL: e.g. new CookieStorage(), to use the specified storage provided (Storage provider used to store session data. By default, it uses localStorage if available or an in-memory structure.)
            //IdentityProvider : '',                    // OPTIONAL: e.g. 'Facebook'
            //UserPoolId : '',                          // OPTIONAL
            //AdvancedSecurityDataCollectionFlag : '',  // OPTIONAL: boolean value indicating whether you want to enable advanced security data collection
        };
        this.auth = new AmazonCognitoIdentity.CognitoAuth(authData);

        // The default response_type is "token" (implicit flow)
        this.auth.useCodeGrantFlow(); // default: this.auth.useImplicitFlow()

        this.auth.userhandler = {
            onSuccess: function (session) {
                const lcsAuth = AWS.config.lcsAuth;

                // Debug log output
                //console.log("Login Success", session);
                //console.log("Email", lcsAuth.getSignedInEmail());
                //console.log("Groups", lcsAuth.getSignedInGroups());
                //console.log("Roles", lcsAuth.getSignedInRoles());

                // session is assumed to be defined and valid since this is a success handler
                const state = session.getState();
                if (state) {
                    const decodedState = lcsAuth.window.decodeURIComponent(state);
                    const stateObj = JSON.parse(lcsAuth.window.atob(decodedState));
                    const pathname = stateObj.pathname;
                    //console.log("State", pathname); // Debug log output

                    lcsAuth.window.history.replaceState(null, null, pathname);
                    lcsAuth.window.location.reload();
                }

                lcsAuth.createCredentials(session);
                AWS.config.getCredentials(function (err) {
                    if (!err) {
                        if (lcsAuth.callback) {
                            lcsAuth.callback(session);
                        }

                        if (lcsAuth.refreshResolver) {
                            lcsAuth.refreshResolver(session);
                        }

                        if (lcsAuth.getSessionResolver) {
                            lcsAuth.getSessionResolver(session);
                        }
                    } else {
                        console.log('AWS.config.getCredentials() error: ' + err);
                        if (lcsAuth.refreshRejecter) {
                            lcsAuth.refreshRejecter(session);
                        }

                        if (lcsAuth.getSessionRejecter) {
                            lcsAuth.getSessionRejecter(session);
                        }
                    }
                });

                return session;
            },
            onFailure: function (err) {
                console.log('initAuthorizer() login error', err);
            },
        };

        // Remember where we came from
        this.setStateToPath();

        // Create initial unauthenticated credentials (null session)
        this.createCredentials(null);

        // Act on any login directives in the URL (as a result of a successful login)
        const curUrl = this.window.location.href;
        this.auth.parseCognitoWebResponse(curUrl); // TODO: wrap in promise and await?
    }

    setStateToPath() {
        if (this.window) {
            const nonce = this.auth.generateRandomString(
                this.auth.getCognitoConstants().STATELENGTH,
                this.auth.getCognitoConstants().STATEORIGINSTRING
            );
            const state = {
                pathname: this.window.location.pathname,
                nonce,
            };
            this.auth.setState(this.window.btoa(JSON.stringify(state)));
        }
    }

    createCredentials(session) {
        var logins = [];
        if (session && this.isUserSignedIn()) {
            logins[lcsConfig.IDENTITY_PROVIDER_COGNITO] = session.getIdToken().getJwtToken();
        }

        // Initialize the Amazon Cognito credentials provider
        AWS.config.region = lcsConfig.REGION;
        AWS.config.credentials = new AWS.CognitoIdentityCredentials({
            IdentityPoolId: lcsConfig.IDENTITY_POOL_ID,
            Logins: logins,
        });
    }

    async checkCredentials(requiresLogin) {
        try {
            // Refresh access token, if necessary
            // We still want to do this if we're on a page
            // that doesn't require login: a user may be
            // logged into a page that doesn't *require* login
            // and need a token refresh.
            if (AWS.config.credentials.needsRefresh() && !this.isUserSignedIn() && this.auth.getCurrentUser()) {
                await this.getRefreshPromise();
            } else if (this.isUserSignedIn() || requiresLogin) {
                if (!this.auth.getCurrentUser()) {
                    // If isUserSignedIn() but !getCurrentUser(), it means we've
                    // been logged out in another window (no creds in cache)
                    // Assigning singInUserSession to the empty cache
                    // forces getSession() to invoke login UI
                    this.auth.signInUserSession = this.auth.getCachedSession();
                }
                await this.getSessionPromise();
            }
        } catch (err) {
            console.log('checkCredentials() error: ' + err);
        }
    }

    getSessionPromise() {
        return new Promise((resolve, reject) => {
            this.getSessionResolver = resolve;
            this.getSessionRejecter = reject;
            this.auth.getSession();
        });
    }

    getRefreshPromise() {
        return new Promise((resolve, reject) => {
            this.refreshResolver = resolve;
            this.refreshRejecter = reject;
            this.auth.refreshSession(this.auth.signInUserSession.getRefreshToken().getToken());
        });
    }

    getIdTokenObj() {
        var tokenObj = null;
        if (this.isUserSignedIn()) {
            const session = this.auth.getSignInUserSession();
            if (session && session.isValid()) {
                const idToken = session.getIdToken();
                const idTokenJwt = idToken.getJwtToken();
                if (idTokenJwt) {
                    var payload = idTokenJwt.split('.')[1];
                    tokenObj = JSON.parse(atob(payload));
                }
            }
        }
        return tokenObj;
    }

    getSignedInEmail() {
        var email = null;
        const tokenObj = this.getIdTokenObj();
        if (tokenObj) {
            email = tokenObj.email;
        }
        return email;
    }

    getSignedInGroups() {
        var groups = null;
        const tokenObj = this.getIdTokenObj();
        if (tokenObj) {
            groups = tokenObj['cognito:groups'];
        }
        return groups;
    }

    getSignedInRoles() {
        var roles = null;
        const tokenObj = this.getIdTokenObj();
        if (tokenObj) {
            roles = tokenObj['cognito:roles'];
        }
        return roles;
    }

    isUserSignedIn() {
        return this.auth.isUserSignedIn();
    }

    signOut() {
        this.auth.signOut();
    }
}
