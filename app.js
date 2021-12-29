// OAuth Dependencies
const OAuth2Server = require('oauth2-server');
const OAuthModel = require("./model/OAuthModel");

// FS Dependencies
const path = require("path");

// Express Dependencies
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);


const app = express();
// load body-parser middleware
app.use(bodyParser.urlencoded({ extended: true }));
// load static middleware
app.use("/assets", express.static("public/assets"));
// load session middleware
app.set('trust proxy', 1);
app.use(session({
    cookie: {
        sameSite: true,
        maxAge: 600000
    },
    resave: false,
    saveUninitialized: false,
    secret: "dfhsdfgeyuefysgaadfasdfrg",
    store: new MemoryStore({
        checkPeriod: 3600000
    })
}));

const oauthModel = new OAuthModel();
const oauth = new OAuth2Server({
    model: oauthModel
});

const port = 8080;

/**
 * GET /
 * Renders Hello World! after login
 */
app.get("/", (request, response) => {
    if (!request.session.login)
        return response.redirect(302, "/login");
    return response.send("Hello World!");
});

/**
 * GET /login
 * Renders login page
 */
app.get("/login", (request, response) => {
    if (request.session.login)
        return response.redirect(302, "/");
    return response.sendFile(path.join(__dirname, "public/login.html"));
});

/**
 * POST /login
 * Authenticates user credentials
 */
app.post("/login", (request, response) => {

    // validate the request
    if (!request.body || !request.body.username || !request.body.password)
        return response.redirect(302, "/login");

    // gather parameters
    const username = request.body.username.trim();
    const password = request.body.password.trim();

    // validate parameters
    if (!username || !password)
        return response.redirect(302, "/login");

    // authenticate user
    oauthModel.getUser(username, password)
        .then((user) => {
            // set session
            request.session.login = true;

            return response.redirect(302, "/");
        })
        .catch((error) => {
            return response.redirect(302, "/login");
        });
});

/**
 * GET /logout
 * Renders login page
 */
app.get("/logout", (request, response) => {
    request.session.destroy((error) => {
        return response.redirect(302, "/login");
    });
});

/**
 * GET /oauth/authorize
 * Renders login page if user is not logged in otherwise renders consent page
 */
app.get("/oauth/authorize", (request, response) => {
    // TODO Implement this one
    response.send("Not yet implemented!");
});

/**
 * POST /oauth/authorize
 * Records user authorization consent to client and redirects to client
 */
app.get("/oauth/authorize/consent", (request, response) => {
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
app.listen(port, () => {
    console.log(`Server Started: Listening on port ${port}`);
});

//// FUTURE IMPLEMENTATION
// oauth.token(new OAuth2Server.Request(request), new OAuth2Server.Response(response))
//     .then((token) => response.send(token))
//     .catch((error) => response.send(error));
// oauth.authenticate(new OAuth2Server.Request(request), new OAuth2Server.Response(response))
//     .then((token) => response.send(token))
//     .catch((error) => response.send(error));