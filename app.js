// OAuth Dependencies
const OAuth2Server = require('oauth2-server');
const OAuthModel = require("./model/OAuthModel");

// FS Dependencies
const fs = require("fs").promises;
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
            request.session.login = user.username;

            // redirect to referred page, if needed
            if (request.session.redirectURL) {
                const redirectURL = request.session.redirectURL;
                request.session.redirectURL = undefined;
                return response.redirect(302, redirectURL);
            }
            else
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
app.get("/oauth/authorize", async (request, response) => {
    // TODO
    // validate each parameters individually
    // send error via callback
    if (!request.query.client_id || !request.query.scope || !request.query.state || !request.query.response_type)
        return response.sendStatus(400);

    const client_id = request.query.client_id.trim();
    const scope = request.query.scope.trim();
    const response_type = request.query.response_type.trim();

    if (!client_id || !scope || !response_type)
        return response.sendStatus(400);

    try {
        await oauthModel.getClient(client_id, null);
        if (!request.session.login) {
            request.session.redirectURL = request.originalUrl;
            return response.redirect(302, "/login");
        }
        else {
            let responseHtml = await fs.readFile(path.join(__dirname, "public/oauth_authorize.html"), { encoding: "utf-8" });
            const formBody = `<input type="hidden" name="client_id" value="${request.query.client_id}" />`
                + `<input type="hidden" name="scope" value="${request.query.scope}" />`
                + `<input type="hidden" name="state" value="${request.query.state}" />`
                + `<input type="hidden" name="response_type" value="${request.query.response_type}"></input>`;
            responseHtml = responseHtml.replace(/{{{form_body}}}/g, formBody);
            return response.send(responseHtml);
        }
    }
    catch (error) {
        response.status(400).send(error);
    }
});

/**
 * POST /oauth/authorize/decline
 * Records user authorization decline and redirects to client
 */
app.post("/oauth/authorize/decline", (request, response) => {
});

/**
 * POST /oauth/authorize/consent
 * Records user authorization consent to client and redirects to client
 */
app.post("/oauth/authorize/consent", (request, response) => {
    // if (!request.session.login) {
    //     return response.redirect(302, "/login");
    // }

    const authorizeOptions = {
        authenticateHandler: {
            handle: (authenticateRequest) => oauthModel.getUserByUsername(authenticateRequest.session.login)
            //handle: (authenticateRequest) => oauthModel.getUser(authenticateRequest.body.username, authenticateRequest.body.password)
        }
    };

    oauth.authorize(new OAuth2Server.Request(request), new OAuth2Server.Response(response), authorizeOptions)
        .then((authorizationCode) => {
            // build callback URL
            const callbackURL = `${authorizationCode.redirectUri}?code=${authorizationCode.authorizationCode}&state=${request.body.state}`;
            response.redirect(302, callbackURL);
        })
        .catch((error) => {
            response.status(400).send(error);
        });
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