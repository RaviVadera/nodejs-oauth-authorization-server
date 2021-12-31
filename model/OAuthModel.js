/**
 * Implementation of OAuth Server 2 Model Specifications
 * @see https://oauth2-server.readthedocs.io/en/latest/model/spec.html
 */
class OAuthModel {

    constructor() {
        this.clients = [{ client_id: "client1", client_secret: "secret", redirect_uris: ["http://localhost:8080/callback"], grants: ["authorization_code"] }];
        this.authorizationCodes = [];
        this.accessTokens = [];
        this.refreshTokens = [];
        this.users = [{ id: "user1", username: "user1", password: "password" }];
        this.VALID_SCOPES = ['read', 'write'];
    }

    // includes default implementation of generateAccessToken(client, user, scope, [callback])
    // see https://oauth2-server.readthedocs.io/en/latest/model/spec.html#generateaccesstoken-client-user-scope-callback

    // includes default implementation of generateRefreshToken(client, user, scope, [callback])
    // see https://oauth2-server.readthedocs.io/en/latest/model/spec.html#generaterefreshtoken-client-user-scope-callback

    // includes default implementation of generateAuthorizationCode(client, user, scope, [callback])
    // see https://oauth2-server.readthedocs.io/en/latest/model/spec.html#generateauthorizationcode-client-user-scope-callback

    /**
     * Invoked to retrieve an existing access token previously saved through {@link OAuthModel#saveToken()}
     * @see https://oauth2-server.readthedocs.io/en/latest/model/spec.html#getaccesstoken-accesstoken-callback
     * @param {String} accessToken The access token to retrieve
     * @returns Promise that resolves to an {@link Object} representing the access token and associated data
     */
    getAccessToken(accessToken) {
        return new Promise((resolve, reject) => {
            if (!accessToken)
                return reject("Parameters must not be null");
            const foundToken = this.accessTokens.find((t) => t.access_token === accessToken);
            if (!foundToken)
                return reject("Access token not found");
            const foundClient = this.clients.find((c) => c.id === foundToken.client_id);
            if (!foundClient)
                return reject("Client not found");
            const foundUser = this.users.find((u) => u.id === foundToken.user_id);
            if (!foundUser)
                return reject("User not found");
            return resolve({
                accessToken: foundToken.access_token,
                accessTokenExpiresAt: foundToken.expires_at,
                scope: foundToken.scope,
                client: foundClient,
                user: foundUser
            });
        });
    }

    /**
     * Invoked to retrieve an existing refresh token previously saved through {@link OAuthModel#saveToken()}
     * @see https://oauth2-server.readthedocs.io/en/latest/model/spec.html#getrefreshtoken-refreshtoken-callback
     * @param {String} refreshToken The access token to retrieve
     * @returns Promise that resolves to an {@link Object} representing the refresh token and associated data
     */
    getRefreshToken(refreshToken) {
        return new Promise((resolve, reject) => {
            if (!refreshToken)
                return reject("Parameters must not be null");
            const foundToken = this.refreshTokens.find((t) => t.refresh_token === refreshToken);
            if (!foundToken)
                return reject("Refresh token not found");
            const foundClient = this.clients.find((c) => c.id === foundToken.client_id);
            if (!foundClient)
                return reject("Client not found");
            const foundUser = this.users.find((u) => u.id === foundToken.user_id);
            if (!foundUser)
                return reject("User not found");
            return resolve({
                refreshToken: foundToken.refresh_token,
                refreshTokenExpiresAt: foundToken.expires_at,
                scope: foundToken.scope,
                client: foundClient,
                user: foundUser
            });
        });
    }

    /**
     * Invoked to retrieve an existing authorization code previously saved through {@link Model#saveAuthorizationCode()}
     * @see https://oauth2-server.readthedocs.io/en/latest/model/spec.html#getauthorizationcode-authorizationcode-callback
     * @param {String} authorizationCode The authorization code to retrieve
     * @returns Promise that resolves to an {@link Object} representing the authorization code and associated data
     */
    getAuthorizationCode(authorizationCode) {
        return new Promise((resolve, reject) => {
            if (!authorizationCode)
                return reject("Parameters must not be null");
            const foundCode = this.authorizationCodes.find((c) => c.authorization_code === authorizationCode);
            if (!foundCode)
                return reject("Authorization code not found");
            const foundClient = this.clients.find((c) => c.id === foundCode.client_id);
            if (!foundClient)
                return reject("Client not found");
            const foundUser = this.users.find((u) => u.id === foundCode.user_id);
            if (!foundUser)
                return reject("User not found");
            return resolve({
                code: foundCode.authorization_code,
                expiresAt: foundCode.expires_at,
                redirectUri: foundCode.redirect_uri,
                scope: foundCode.scope,
                client: foundClient,
                user: foundUser
            });
        });
    }

    /**
     * Invoked to retrieve a client using a client id or a client id/client secret combination, depending on the grant type
     * @see https://oauth2-server.readthedocs.io/en/latest/model/spec.html#getclient-clientid-clientsecret-callback
     * @param {String} clientId The client id of the client to retrieve
     * @param {String} clientSecret The client secret of the client to retrieve. Can be null
     * @returns Promise that resolves to an {@link Object} representing the client and associated data, or a falsy value if no such client could be found
     */
    getClient(clientId, clientSecret) {
        return new Promise((resolve, reject) => {
            if (!clientId)
                return reject("Parameters must not be null");
            let foundClient;
            if (clientSecret)
                foundClient = this.clients.find((c) => c.client_id === clientId && c.client_secret === clientSecret);
            else
                foundClient = this.clients.find((c) => c.client_id === clientId);
            if (!foundClient)
                return reject("Client not found");
            return resolve({
                id: foundClient.id,
                redirectUris: foundClient.redirect_uris,
                grants: foundClient.grants
            });
        });
    }

    /**
     * Invoked to retrieve a user using a username/password combination
     * @see https://oauth2-server.readthedocs.io/en/latest/model/spec.html#getuser-username-password-callback
     * @param {String} username The username of the user to retrieve
     * @param {String} password The user’s password
     * @returns Promise that resolves to an {@link Object} representing the user, or a falsy value if no such user could be found. The user object is completely transparent to oauth2-server and is simply used as input to other model functions
     */
    getUser(username, password) {
        return new Promise((resolve, reject) => {
            if (!username || !password)
                return reject("Parameters must not be null");
            const foundUser = this.users.find((u) => u.username === username && u.password == password);
            if (!foundUser)
                return reject("User not found");
            return resolve(foundUser);
        });
    }

    /**
     * @see https://oauth2-server.readthedocs.io/en/latest/model/spec.html#getuserfromclient-client-callback
     * @param {Object} client The client to retrieve the associated user for
     * @returns Promise that resolves to an {@link Object} representing the user, or a falsy value if the client does not have an associated user. The user object is completely transparent to oauth2-server and is simply used as input to other model functions.
     */
    getUserFromClient(client) {
        return new Promise((resolve, reject) => {
            if (!client)
                return reject("Parameters must not be null");
            const foundUser = this.users.find((u) => u.id === client.user_id);
            if (!foundUser)
                return reject("User not found");
            return resolve(foundUser);
        });
    }

    /**
     * Invoked to save an authorization code
     * @see https://oauth2-server.readthedocs.io/en/latest/model/spec.html#saveauthorizationcode-code-client-user-callback
     * @param {Object} code The code to be saved
     * @param {Object} client The client associated with the authorization code
     * @param {Object} user The user associated with the authorization code
     * @returns Promise that resolves to an {@link Object} representing the authorization code and associated data
     */
    saveAuthorizationCode(code, client, user) {
        return new Promise((resolve, reject) => {
            if (!code || !client || !user)
                return reject("Parameters must not be null");
            const authorizationCode = {
                authorization_code: code.authorizationCode,
                expires_at: code.expiresAt,
                redirect_uri: code.redirectUri,
                scope: code.scope,
                client_id: client.id,
                user_id: user.id
            };
            this.authorizationCodes.push(authorizationCode);
            return resolve({
                authorizationCode: authorizationCode.authorization_code,
                expiresAt: authorizationCode.expires_at,
                redirectUri: authorizationCode.redirect_uri,
                scope: authorizationCode.scope,
                client: { id: authorizationCode.client_id },
                user: { id: authorizationCode.user_id }
            });
        });
    }

    /**
     * Invoked to save an access token and optionally a refresh token, depending on the grant type
     * @see https://oauth2-server.readthedocs.io/en/latest/model/spec.html#savetoken-token-client-user-callback
     * @param {Object} token The token(s) to be saved
     * @param {Object} client The client associated with the token(s)
     * @param {Object} user The user associated with the token(s)
     * @returns Promise that resolves to an {@link Object} representing the token(s) and associated data
     */
    saveToken(token, client, user) {
        return new Promise((resolve, reject) => {
            if (!token || !client || !user)
                return reject("Parameters must not be null");
            const accessToken = {
                access_token: token.accessToken,
                expires_at: token.accessTokenExpiresAt,
                scope: token.scope,
                client_id: client.id,
                user_id: user.id
            };
            const refreshToken = {
                refresh_token: token.refreshToken,
                expires_at: token.refreshTokenExpiresAt,
                scope: token.scope,
                client_id: client.id,
                user_id: user.id
            };
            this.accessTokens.push(accessToken);
            this.refreshTokens.push(refreshToken);
            return resolve({
                accessToken: accessToken.access_token,
                accessTokenExpiresAt: accessToken.expires_at,
                refreshToken: refreshToken.refresh_token,
                refreshTokenExpiresAt: refreshToken.expires_at,
                scope: accessToken.scope,
                client: { id: accessToken.client_id },
                user: { id: accessToken.user_id }
            });
        });
    }

    /**
     * Invoked to revoke a refresh token
     * @see https://oauth2-server.readthedocs.io/en/latest/model/spec.html#revoketoken-token-callback
     * @param {Object} refreshToken The token to be revoked
     * @returns Promise that resolves to true if the revocation was successful or false if the refresh token could not be found
     */
    revokeToken(refreshToken) {
        return new Promise((resolve, reject) => {
            const foundIndex = this.refreshTokens.indexOf(refreshToken);
            if (foundIndex === -1)
                return reject("Refresh token not found");
            const removedToken = this.refreshTokens.splice(foundIndex, 1);
            return resolve(!!removedToken);
        });
    }

    /**
     * Invoked to revoke an authorization code
     * @see https://oauth2-server.readthedocs.io/en/latest/model/spec.html#revokeauthorizationcode-code-callback
     * @param {Object} authorizationCode The code to be revoked
     * @returns Promise that resolves to true if the revocation was successful or false if the authorization code could not be found
     */
    revokeAuthorizationCode(authorizationCode) {
        return new Promise((resolve, reject) => {
            const foundIndex = this.authorizationCodes.indexOf(authorizationCode);
            if (foundIndex === -1)
                return reject("Authorization code not found");
            const removedCode = this.authorizationCodes.splice(foundIndex, 1);
            return resolve(!!removedCode);
        });
    }

    /**
     * Invoked to check if the requested scope is valid for a particular client/user combination
     * @see https://oauth2-server.readthedocs.io/en/latest/model/spec.html#validatescope-user-client-scope-callback
     * @param {Object} user The associated user
     * @param {Object} client The associated client
     * @param {String} scope The scopes to validate
     * @returns Promise that resolves to validated scopes to be used or a falsy value to reject the requested scopes
     */
    validateScope(user, client, scope) {
        return new Promise((resolve, reject) => {
            const foundClient = this.clients.find((c) => c.id === client.client_id);
            if (!foundClient)
                return reject("Client not found");
            const foundUser = this.users.find((u) => u.id === user.id);
            if (!foundUser)
                return reject("User not found");
            if (!scope.split(' ').every(s => this.VALID_SCOPES.indexOf(s) >= 0))
                return reject("Scopes are not valid");
            return resolve(true);
        });
    }

    /**
     * Invoked during request authentication to check if the provided access token was authorized the requested scopes
     * @see https://oauth2-server.readthedocs.io/en/latest/model/spec.html#verifyscope-accesstoken-scope-callback
     * @param {Object} accessToken The access token to test against
     * @param {String} scope The required scopes
     * @returns Promise that resolved to true if the access token passes, false otherwise
     */
    verifyScope(accessToken, scope) {
        return new Promise((resolve, reject) => {
            if (!accessToken.scope)
                return reject("Token does not specify scope");

            const requestedScopes = scope.split(' ');
            const authorizedScopes = accessToken.scope.split(' ');
            if (!requestedScopes.every(s => authorizedScopes.indexOf(s) >= 0))
                return reject("Scopes does not match");
            return resolve(true);
        });
    }
}
module.exports = OAuthModel;