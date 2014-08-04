var Cookie     = require('cookie');
var csrfTokens = require('csrf-tokens');
var sign       = require('cookie-signature').sign;


var ignoreMethod = {
    GET:        true,
    HEAD:       true,
    OPTIONS:    true
};


module.exports = function csurf (options) {


    options    = options || {};

    var value  = options.value || defaultValue;
    var tokens = csrfTokens(options);

    if (options.cookie && !options.cookie.key) options.cookie.key = '_csrf';


    return function csrf (req, res, next) {

        var secret = getSecret(req, options.cookie);
        var token;
        var err;

        if (secret instanceof Error) return res.json(500, { csrf: secret.toString() });


        req.csrfToken = function csrfToken () {

            var err;

            if (options.cookie) {
                sec = secret;

            } else {
                sec = getSecret(req, options.cookie);
                if (sec instanceof Error) return res.json(500, { csrf: sec.toString() });
            }

            if (token && sec === secret) return token;

            if (sec === undefined) {
                sec = tokens.secretSync();
                err = setSecret(req, res, sec, options.cookie);
                if (err instanceof Error) return res.json(500, { csrf: err.toString() });
            }

            secret = sec;
            token  = tokens.create(secret);

            return token;
        };


        if (!secret) {
            secret = tokens.secretSync();
            err = setSecret(req, res, secret, options.cookie);
            if (err instanceof Error) return res.json(500, { csrf: err.toString() });
        }

        err = verifyToken(req, tokens, secret, value(req));
        if (err instanceof Error) return res.json(403, { csrf: err.toString() });

        next();
    }
};



function defaultValue (req) {
    return (req.body && req.body._csrf)
        || (req.query && req.query._csrf)
        || (req.headers['x-csrf-token'])
        || (req.headers['x-xsrf-token']);
}



function getSecret (req, cookie) {

    var secret;

    if (cookie) {
        var bag = (cookie.signed) ? 'signedCookies' : 'cookies';
        secret  = req[bag][cookie.key];

    } else if (req.session) {
        secret = req.session.csrfSecret;

    } else {
        return new Error('misconfigured csrf');
    }

    return secret;
}



function setCookie (res, name, val, options) {

    var data   = Cookie.serialize(name, val, options);
    var prev   = res.getHeader('set-cookie') || [];
    var header = Array.isArray(prev) ? prev.concat(data) : 
                 Array.isArray(data) ? [prev].concat(data) : 
                 [prev, data];

    res.setHeader('set-cookie', header);
}



function setSecret (req, res, val, cookie) {

    var secret;

    if (cookie) {
        if (cookie.signed) {
            secret = req.secret;
            if (!secret) return new Error('cookieParser("secret") required for signed cookies');
            val = 's:' + sign(val, secret);
        }

        setCookie(res, cookie.key, val, cookie);

    } else if (req.session) {
        req.session.csrfSecret = val;

    } else {
        return new Error('misconfigured csrf');
    }
}



function verifyToken (req, tokens, secret, val) {

    if (ignoreMethod[req.method] || tokens.verify(secret, val)) return;

    return new Error('invalid csrf token');
}
