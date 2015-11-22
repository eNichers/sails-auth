/**
 * Authentication Controller
 */
module.exports = {

  /**
   * Log out a employee and return them to the homepage
   *
   * Passport exposes a logout() function on req (also aliased as logOut()) that
   * can be called from any route handler which needs to terminate a login
   * session. Invoking logout() will remove the req.employee property and clear the
   * login session (if any).
   *
   * For more information on logging out employees in Passport.js, check out:
   * http://passportjs.org/guide/logout/
   *
   * @param {Object} req
   * @param {Object} res
   */
  logout: function (req, res) {
    req.logout();
    delete req.employee;
    delete req.session.passport;
    req.session.authenticated = false;
    
    if (!req.isSocket) {
      res.redirect(req.query.next || '/');
    }
    else {
      res.ok();
    }
  },

  /**
   * Create a third-party authentication endpoint
   *
   * @param {Object} req
   * @param {Object} res
   */
  provider: function (req, res) {
    sails.services.passport.endpoint(req, res);
  },

  /**
   * Create a authentication callback endpoint
   *
   * This endpoint handles everything related to creating and verifying Pass-
   * ports and employees, both locally and from third-aprty providers.
   *
   * Passport exposes a login() function on req (also aliased as logIn()) that
   * can be used to establish a login session. When the login operation
   * completes, employee will be assigned to req.employee.
   *
   * For more information on logging in employees in Passport.js, check out:
   * http://passportjs.org/guide/login/
   *
   * @param {Object} req
   * @param {Object} res
   */
  callback: function (req, res) {
    function tryAgain (err) {

      // Only certain error messages are returned via req.flash('error', someError)
      // because we shouldn't expose internal authorization errors to the employee.
      // We do return a generic error and the original request body.
      var flashError = req.flash('error')[0];
      if (err || flashError) {
        sails.log.warn(err);
        sails.log.warn(flashError);
      }

      if (err && !flashError ) {
        req.flash('error', 'Error.Passport.Generic');
      }
      else if (flashError) {
        req.flash('error', flashError);
      }
      req.flash('form', req.body);

      // If an error was thrown, redirect the employee to the
      // login, register or disconnect action initiator view.
      // These views should take care of rendering the error messages.
      var action = req.param('action');

      if (action === 'register') {
        res.redirect('/register');
      }
      else if (action === 'login') {
        res.redirect('/login');
      }
      else if (action === 'disconnect') {
        res.redirect('back');
      }
      else {
        // make sure the server always returns a response to the client
        // i.e passport-local bad employeeName/email or password
        res.forbidden();
      }

    }

      sails.services.passport.callback(req, res, function (err, employee) {

      if (err || !employee) {
        sails.log.warn(err);
        return tryAgain();
      }

      req.login(employee, function (err) {
        if (err) {
          sails.log.warn(err);
          return tryAgain();
        }

        req.session.authenticated = true;

        // Upon successful login, optionally redirect the employee if there is a
        // `next` query param
        if (req.query.next) {
          res.status(302).set('Location', req.query.next);
        }

        sails.log.info('employee', employee, 'authenticated successfully');
        return res.json(employee);
      });
    });
  },

  /**
   * Disconnect a passport from a employee
   *
   * @param {Object} req
   * @param {Object} res
   */
  disconnect: function (req, res) {
    sails.services.passport.disconnect(req, res);
  }
};
