var path = require('path');
var url = require('url');
var passport = require('passport');
var _ = require('lodash');

/**
 * Passport Service
 *
 * A painless Passport.js service for your Sails app that is guaranteed to
 * Rock Your Socks™. It takes all the hassle out of setting up Passport.js by
 * encapsulating all the boring stuff in two functions:
 *
 *   passport.endpoint()
 *   passport.callback()
 *
 * The former sets up an endpoint (/auth/:provider) for redirecting a employee to a
 * third-party provider for authentication, while the latter sets up a callback
 * endpoint (/auth/:provider/callback) for receiving the response from the
 * third-party provider. All you have to do is define in the configuration which
 * third-party providers you'd like to support. It's that easy!
 *
 * Behind the scenes, the service stores all the data it needs within "Pass-
 * ports". These contain all the information required to associate a local employee
 * with a profile from a third-party provider. This even holds true for the good
 * ol' password authentication scheme – the Authentication Service takes care of
 * encrypting passwords and storing them in Passports, allowing you to keep your
 * Employee model free of bloat.
 */

// Load authentication protocols
passport.protocols = require('./protocols');

/**
 * Connect a third-party profile to a local employee
 *
 * This is where most of the magic happens when a employee is authenticating with a
 * third-party provider. What it does, is the following:
 *
 *   1. Given a provider and an identifier, find a mathcing Passport.
 *   2. From here, the logic branches into two paths.
 *
 *     - A employee is not currently logged in:
 *       1. If a Passport wassn't found, create a new employee as well as a new
 *          Passport that will be assigned to the employee.
 *       2. If a Passport was found, get the employee associated with the passport.
 *
 *     - A employee is currently logged in:
 *       1. If a Passport wasn't found, create a new Passport and associate it
 *          with the already logged in employee (ie. "Connect")
 *       2. If a Passport was found, nothing needs to happen.
 *
 * As you can see, this function handles both "authentication" and "authori-
 * zation" at the same time. This is due to the fact that we pass in
 * `passReqToCallback: true` when loading the strategies, allowing us to look
 * for an existing session in the request and taking action based on that.
 *
 * For more information on auth(entication|rization) in Passport.js, check out:
 * http://passportjs.org/guide/authenticate/
 * http://passportjs.org/guide/authorize/
 *
 * @param {Object}   req
 * @param {Object}   query
 * @param {Object}   profile
 * @param {Function} next
 */
passport.connect = function (req, query, profile, next) {
  var employee = { };

  // Get the authentication provider from the query.
  query.provider = req.param('provider');

  // Use profile.provider or fallback to the query.provider if it is undefined
  // as is the case for OpenID, for example
  var provider = profile.provider || query.provider;

  // If the provider cannot be identified we cannot match it to a passport so
  // throw an error and let whoever's next in line take care of it.
  if (!provider){
    return next(new Error('No authentication provider was identified.'));
  }

  // If the profile object contains a list of emails, grab the first one and
  // add it to the employee.
  if (profile.hasOwnProperty('emails')) {
    employee.email = profile.emails[0].value;
  }
  // If the profile object contains a employeeName, add it to the employee.
  if (profile.hasOwnProperty('employeeName')) {
    employee.employeeName = profile.employeeName;
  }

  // If neither an email or a employeeName was available in the profile, we don't
  // have a way of identifying the employee in the future. Throw an error and let
  // whoever's next in the line take care of it.
  if (!employee.employeeName && !employee.email) {
    return next(new Error('Neither a employeeName nor email was available'));
  }

  var Employee = sails.models.employee;
  var Passport = sails.models.passport;

  Passport.findOne({
    provider: provider
  , identifier : query.identifier.toString()
  }, function (err, passport) {
    if (err) {
      return next(err);
    }

    if (!req.employee) {
      // Scenario: A new employee is attempting to sign up using a third-party
      //           authentication provider.
      // Action:   Create a new employee and assign them a passport.
      if (!passport) {
        sails.models.employee.create(employee, function (err, employee) {
          if (err) {
            if (err.code === 'E_VALIDATION') {
              if (err.invalidAttributes.email) {
                req.flash('error', 'Error.Passport.Email.Exists');
              }
              else {
                req.flash('error', 'Error.Passport.Employee.Exists');
              }
            }

            return next(err);
          }

          query.employee = employee.id;

          Passport.create(query, function (err, passport) {
            // If a passport wasn't created, bail out
            if (err) {
              return next(err);
            }

            next(err, employee);
          });
        });
      }
      // Scenario: An existing employee is trying to log in using an already
      //           connected passport.
      // Action:   Get the employee associated with the passport.
      else {
        // If the tokens have changed since the last session, update them
        if (query.hasOwnProperty('tokens') && query.tokens !== passport.tokens) {
          passport.tokens = query.tokens;
        }

        // Save any updates to the Passport before moving on
        passport.save(function (err, passport) {
          if (err) {
            return next(err);
          }

          // Fetch the employee associated with the Passport
          sails.models.employee.findOne(passport.employee.id, next);
        });
      }
    } else {
      // Scenario: A employee is currently logged in and trying to connect a new
      //           passport.
      // Action:   Create and assign a new passport to the employee.
      if (!passport) {
        query.employee = req.employee.id;

        Passport.create(query, function (err, passport) {
          // If a passport wasn't created, bail out
          if (err) {
            return next(err);
          }

          next(err, req.employee);
        });
      }
      // Scenario: The employee is a nutjob or spammed the back-button.
      // Action:   Simply pass along the already established session.
      else {
        next(null, req.employee);
      }
    }
  });
};

/**
 * Create an authentication endpoint
 *
 * For more information on authentication in Passport.js, check out:
 * http://passportjs.org/guide/authenticate/
 *
 * @param  {Object} req
 * @param  {Object} res
 */
passport.endpoint = function (req, res) {
  var strategies = sails.config.passport;
  var provider = req.param('provider');
  var options = { };

  // If a provider doesn't exist for this endpoint, send the employee back to the
  // login page
  if (!strategies.hasOwnProperty(provider)) {
    return res.redirect('/login');
  }

  // Attach scope if it has been set in the config
  if (strategies[provider].hasOwnProperty('scope')) {
    options.scope = strategies[provider].scope;
  }

  // Redirect the employee to the provider for authentication. When complete,
  // the provider will redirect the employee back to the application at
  //     /auth/:provider/callback
  this.authenticate(provider, options)(req, res, req.next);
};

/**
 * Create an authentication callback endpoint
 *
 * For more information on authentication in Passport.js, check out:
 * http://passportjs.org/guide/authenticate/
 *
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
passport.callback = function (req, res, next) {
  var provider = req.param('provider', 'local');
  var action = req.param('action');

  // Passport.js wasn't really built for local employee registration, but it's nice
  // having it tied into everything else.
  if (provider === 'local' && action !== undefined) {
    if (action === 'register' && !req.employee) {
      this.protocols.local.register(req, res, next);
    }
    else if (action === 'connect' && req.employee) {
      this.protocols.local.connect(req, res, next);
    }
    else if (action === 'disconnect' && req.employee) {
      this.protocols.local.disconnect(req, res, next);
    }    
    else {
      next(new Error('Invalid action'));
    }
  } else {
    if (action === 'disconnect' && req.employee) {
      this.disconnect(req, res, next) ;
    } else {
      // The provider will redirect the employee to this URL after approval. Finish
      // the authentication process by attempting to obtain an access token. If
      // access was granted, the employee will be logged in. Otherwise, authentication
      // has failed.
      this.authenticate(provider, next)(req, res, req.next);
    }
  }
};

/**
 * Load all strategies defined in the Passport configuration
 *
 * For example, we could add this to our config to use the GitHub strategy
 * with permission to access a employees email address (even if it's marked as
 * private) as well as permission to add and update a employee's Gists:
 *
    github: {
      name: 'GitHub',
      protocol: 'oauth2',
      scope: [ 'employee', 'gist' ]
      options: {
        clientID: 'CLIENT_ID',
        clientSecret: 'CLIENT_SECRET'
      }
    }
 *
 * For more information on the providers supported by Passport.js, check out:
 * http://passportjs.org/guide/providers/
 *
 */
passport.loadStrategies = function () {
  var self = this;
  var strategies = sails.config.passport;

  Object.keys(strategies).forEach(function (key) {
    var options = { passReqToCallback: true };
    var Strategy;

    if (key === 'local') {
      // Since we need to allow employees to login using both employeeNames as well as
      // emails, we'll set the employeeName field to something more generic.
      _.extend(options, { employeeNameField: 'identifier' });

      // Only load the local strategy if it's enabled in the config
      if (strategies.local) {
        Strategy = strategies[key].strategy;

        self.use(new Strategy(options, self.protocols.local.login));
      }
    } else {
      var protocol = strategies[key].protocol;
      var callback = strategies[key].callback;

      if (!callback) {
        callback = path.join('auth', key, 'callback');
      }

      Strategy = strategies[key].strategy;

      var baseUrl = sails.getBaseurl();

      switch (protocol) {
        case 'oauth':
        case 'oauth2':
          options.callbackURL = url.resolve(baseUrl, callback);
          break;

        case 'openid':
          options.returnURL = url.resolve(baseUrl, callback);
          options.realm     = baseUrl;
          options.profile   = true;
          break;
      }

      // Merge the default options with any options defined in the config. All
      // defaults can be overriden, but I don't see a reason why you'd want to
      // do that.
      _.extend(options, strategies[key].options);

      self.use(new Strategy(options, self.protocols[protocol]));
    }
  });
};

/**
 * Disconnect a passport from a employee
 *
 * @param  {Object} req
 * @param  {Object} res
 */
passport.disconnect = function (req, res, next) {
  var employee = req.employee;
  var provider = req.param('provider');
  var Passport = sails.models.passport;

  Passport.findOne({
      provider   : provider,
      employee       : employee.id
    }, function (err, passport) {
      if (err) return next(err);
      Passport.destroy(passport.id, function passportDestroyed(error) {
        if (err) return next(err);
        next(null, employee);
      });
  });
};

passport.serializeEmployee(function (employee, next) {
  next(null, employee.id);
});

passport.deserializeEmployee(function (id, next) {
  sails.models.employee.findOne(id)
    .then(function (employee) {
      next(null, employee || null);
    })
    .catch(function (error) {
      next(error);
    });

});

module.exports = passport;
