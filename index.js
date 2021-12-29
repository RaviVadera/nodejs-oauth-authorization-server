const OAuth2Server = require('oauth2-server');
const OAuthModel = require("./model/OAuthModel");
const express = require('express');
const bodyParser = require('body-parser');

const routes = express();
routes.use(bodyParser.urlencoded({ extended: true }));
const port = 8080;
const oauthModel = new OAuthModel();
const oauth = new OAuth2Server({
    model: oauthModel
});

/**
 * GET /
 * Renders Hello World! after login
 */
routes.get("/", (request, response) => {
    response.send("Hello World!");
});

/**
 * GET /login
 * Renders login page
 */
routes.get("/login", (request, response) => {
    // TODO Implement this one
    response.send("Not yet implemented!");
});

/**
 * GET /oauth/authorize
 * Renders login page if user is not logged in otherwise renders consent page
 */
routes.get("/oauth/authorize", (request, response) => {
    // TODO Implement this one
    response.send("Not yet implemented!");
});

/**
 * POST /oauth/authorize
 * Records user authorization consent to client and redirects to client
 */
routes.get("/oauth/authorize/consent", (request, response) => {
    // TODO Implement this one

    // Partial implementation
    const authorizeOptions = {
        authenticateHandler: {
            handle: (authenticateRequest) => {
                return oauthModel.getUser(authenticateRequest.body.username, authenticateRequest.body.password);
            }
        }
    };

    oauth.authorize(new OAuth2Server.Request(request), new OAuth2Server.Response(response), authorizeOptions)
        .then((token) => response.send(token))
        .catch((error) => response.send(error));
    
    response.send("Not yet implemented!");
});

// start listening for requests on specified port on local machine
routes.listen(port, () => {
    console.log(`Server Started: Listening on port ${port}`);
});

//// FUTURE IMPLEMENTATION
// oauth.token(new OAuth2Server.Request(request), new OAuth2Server.Response(response))
//     .then((token) => response.send(token))
//     .catch((error) => response.send(error));
// oauth.authenticate(new OAuth2Server.Request(request), new OAuth2Server.Response(response))
//     .then((token) => response.send(token))
//     .catch((error) => response.send(error));