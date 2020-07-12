'use strict';

const lcsConfig = {
    // AWS Cognito Constants
    REGION: <YOUR_AWS_REGION>,
    CLIENT_ID: <YOUR_COGNITO_CLIENT_ID>,
    APP_WEB_DOMAIN: <YOUR_COGNITO_APP_WEB_DOMAIN>, // always exclude the "https://" part
    TOKEN_SCOPES_ARRAY: <YOUR_TOKEN_SCOPES_ARRAY>, // like ['aws.cognito.signin.user.admin', 'email', 'openid', 'phone', 'profile']
    REDIRECT_URI_SIGN_IN: <YOUR_REDIRECT_URI_SIGN_IN>,
    REDIRECT_URI_SIGN_OUT: <YOUR_REDIRECT_URI_SIGN_OUT>,
    IDENTITY_POOL_ID: <YOUR_IDENTITY_POOL_ID>,
    IDENTITY_PROVIDER_COGNITO: <YOUR_IDENTITY_PROVIDER_COGNITO>,
};
