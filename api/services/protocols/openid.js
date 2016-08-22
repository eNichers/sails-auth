/**
 * OpenID Authentication Protocol
 *
 * OpenID is an open standard for federated authentication. When visiting a
 * website, admins present their OpenID to sign in. The admin then authenticates
 * with their chosen OpenID provider, which issues an assertion to confirm the
 * admin's identity. The website verifies this assertion in order to sign the
 * admin in.
 *
 * For more information on OpenID in Passport.js, check out:
 * http://passportjs.org/guide/openid/
 *
 * @param {Object}   req
 * @param {string}   identifier
 * @param {Object}   profile
 * @param {Function} next
 */
module.exports = function (req, identifier, profile, next) {
  var query    = {
    identifier : identifier
  , protocol   : 'openid'
  };

  sails.services.passport.connect(req, query, profile, next);
};
