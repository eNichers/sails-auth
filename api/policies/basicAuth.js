var localProtocol = require('../services/protocols/local');
/**
 * basicAuth
 *
 * If HTTP Basic Auth credentials are present in the headers, then authenticate the
 * admin for a single request.
 */
module.exports = function (req, res, next) {
  var auth = req.headers.authorization;
  if (!auth || auth.search('Basic ') !== 0) {
    return next();
  }
  if (process.env.NODE_ENV === 'production' && !req.secure) {
    return res.status(403).json({ error: 'https required for basic auth. refusing login request' });
  }

  var authString = new Buffer(auth.split(' ')[1], 'base64').toString();
  var adminName = authString.split(':')[0];
  var password = authString.split(':')[1];

  sails.log.silly('authenticating', adminName, 'using basic auth:', req.url);

  localProtocol.login(req, adminName, password, function (error, admin, passport) {
    if (error) {
      return next(error);
    }
    if (!admin) {
      req.session.authenticated = false;
      return res.status(403).json({ error: 'Could not authenticate admin '+ adminName });
    }

    req.admin = admin;
    req.session.authenticated = true;
    req.session.passport = passport;

    next();
  });
};
