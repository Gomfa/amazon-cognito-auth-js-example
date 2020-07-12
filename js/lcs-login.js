// The intent of login.js is to encapsulate all of the UI-related
// logic for logging in and out.
// DEPENDENCIES: lcs-auth.js, login header HTML

class LCSLogin {
    static doLogin(requiresLogin) {
        document.getElementById('signInButton').addEventListener('click', function () {
            LCSLogin.onLoginButtonClick();
        });

        // Start by assuming we're logged out
        LCSLogin.showLoggedOut();

        // Initialize and store the LCSAuth object
        AWS.config.lcsAuth = new LCSAuth(window, function (session) {
            // Called upon successful unauth->login
            LCSLogin.showLoggedIn(session);
        });

        LCSLogin.checkCredentials(requiresLogin);
    }

    // TODO: parameter should take minimum required login group ("admin", "registered", etc)
    static async checkCredentials(requiresLogin) {
        await AWS.config.lcsAuth.checkCredentials(requiresLogin); // TODO: remove?
    }

    static doLogout() {
        AWS.config.lcsAuth.signOut();

        // Will never reach this line since the above redirects
        // but including for completeness
        LCSLogin.showLoggedOut();
    }

    static onLoginButtonClick() {
        if (AWS.config.lcsAuth.isUserSignedIn()) {
            // Signed In -> Sign Out
            LCSLogin.doLogout();
        } else {
            // Signed Out -> Sign In
            LCSLogin.doLogin(true); // using "true" as parameter here to ensure the login UI will be invoked
        }
    }

    static showLoggedIn(session) {
        document.getElementById('signInButton').innerHTML = 'Sign Out';
        document.getElementById('userEmail').innerHTML = AWS.config.lcsAuth.getSignedInEmail();

        // Debug UI (if uncommented in login.html)
        if (document.getElementById('tokens')) {
            if (session && session.isValid()) {
                const idToken = session.getIdToken().getJwtToken();
                if (idToken) {
                    const payload = idToken.split('.')[1];
                    const tokenobj = JSON.parse(atob(payload));
                    const formatted = JSON.stringify(tokenobj, undefined, 2);
                    document.getElementById('idToken').innerHTML = 'ID Token: ' + formatted;
                }
                const accToken = session.getAccessToken().getJwtToken();
                if (accToken) {
                    const payload = accToken.split('.')[1];
                    const tokenobj = JSON.parse(atob(payload));
                    const formatted = JSON.stringify(tokenobj, undefined, 2);
                    document.getElementById('accToken').innerHTML = 'Access Token: ' + formatted;
                }
                const refToken = session.getRefreshToken().getToken();
                if (refToken) {
                    document.getElementById('refToken').innerHTML =
                        'Refresh Token (fragment): ' + refToken.substring(1, 20);
                }
            }
            document.getElementById('tokens').style.display = 'block';
        }
    }

    static showLoggedOut() {
        document.getElementById('signInButton').innerHTML = 'Sign In';

        // Debug UI (if uncommented in login.html)
        if (document.getElementById('tokens')) {
            document.getElementById('tokens').style.display = 'none';
            document.getElementById('userEmail').innerHTML = '';
            document.getElementById('idToken').innerHTML = '';
            document.getElementById('accToken').innerHTML = '';
            document.getElementById('refToken').innerHTML = '';
        }
    }
}
