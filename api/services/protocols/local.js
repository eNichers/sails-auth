var SAError = require('../../../lib/error/SAError.js');

/**
 * Local Authentication Protocol
 *
 * The most widely used way for websites to authenticate admins is via a adminName
 * and/or email as well as a password. This module provides functions both for
 * registering entirely new admins, assigning passwords to already registered
 * admins and validating login requesting.
 *
 * For more information on local authentication in Passport.js, check out:
 * http://passportjs.org/guide/adminName-password/
 */

/**
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
exports.register = function (admin, next) {
  exports.createAdmin(admin, next);
};

/**
 * Register a new admin
 *
 * This method creates a new admin from a specified email, adminName and password
 * and assign the newly created admin a local Passport.
 *
 * @param {String}   adminName
 * @param {String}   email
 * @param {String}   password
 * @param {Function} next
 */
exports.createAdmin = function (_admin, next) {
  var password = _admin.password;
  delete _admin.password;

  return sails.models.admin.create(_admin, function (err, admin) {
    if (err) {
      sails.log(err);

      if (err.code === 'E_VALIDATION') {
        return next(new SAError({originalError: err}));
      }
      
      return next(err);
    }

    sails.models.passport.create({
      protocol : 'local'
    , password : password
    , admin     : admin.id
    }, function (err, passport) {
      if (err) {
        if (err.code === 'E_VALIDATION') {
          err = new SAError({originalError: err});
        }
        
        return admin.destroy(function (destroyErr) {
          next(destroyErr || err);
        });
      }

      next(null, admin);
    });
  });
};

/**
 * Assign local Passport to admin
 *
 * This function can be used to assign a local Passport to a admin who doens't
 * have one already. This would be the case if the admin registered using a
 * third-party service and therefore never set a password.
 *
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
exports.connect = function (req, res, next) {
  var admin     = req.admin
    , password = req.param('password')
    , Passport = sails.models.passport;

  Passport.findOne({
    protocol : 'local'
  , admin     : admin.id
  }, function (err, passport) {
    if (err) {
      return next(err);
    }

    if (!passport) {
      Passport.create({
        protocol : 'local'
      , password : password
      , admin     : admin.id
      }, function (err, passport) {
        next(err, admin);
      });
    }
    else {
      next(null, admin);
    }
  });
};

/**
 * Validate a login request
 *
 * Looks up a admin using the supplied identifier (email or adminName) and then
 * attempts to find a local Passport associated with the admin. If a Passport is
 * found, its password is checked against the password supplied in the form.
 *
 * @param {Object}   req
 * @param {string}   identifier
 * @param {string}   password
 * @param {Function} next
 */
exports.login = function (req, identifier, password, next) {
  var isEmail = validateEmail(identifier)
    , query   = {};

  if (isEmail) {
    query.email = identifier;
  }
  else {
    query.adminName = identifier;
  }

  sails.models.admin.findOne(query, function (err, admin) {
    if (err) {
      return next(err);
    }

    if (!admin) {
      if (isEmail) {
        req.flash('error', 'Error.Passport.Email.NotFound');
      } else {
        req.flash('error', 'Error.Passport.adminName.NotFound');
      }

      return next(null, false);
    }

    sails.models.passport.findOne({
      protocol : 'local'
    , admin     : admin.id
    }, function (err, passport) {
      if (passport) {
        Passport.validatePassword(passport, password, function (err, res) {
          if (err) {
            return next(err);
          }

          if (!res) {
            req.flash('error', 'Error.Passport.Password.Wrong');
            return next(null, false);
          } else {
            return next(null, admin, passport);
          }
        });
      }
      else {
        req.flash('error', 'Error.Passport.Password.NotSet');
        return next(null, false);
      }
    });
  });
};

var EMAIL_REGEX = /^((([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+(\.([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+)*)|((\x22)((((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(([\x01-\x08\x0b\x0c\x0e-\x1f\x7f]|\x21|[\x23-\x5b]|[\x5d-\x7e]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(\\([\x01-\x09\x0b\x0c\x0d-\x7f]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]))))*(((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(\x22)))@((([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.)+(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))$/i;

/**
 * Use validator module isEmail function
 *
 * @see <https://github.com/chriso/validator.js/blob/3.18.0/validator.js#L38>
 * @see <https://github.com/chriso/validator.js/blob/3.18.0/validator.js#L141-L143>
 */
function validateEmail (str) {
  return EMAIL_REGEX.test(str);
}
