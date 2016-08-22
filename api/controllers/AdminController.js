/**
 * AdminController
 *
 * @description :: Server-side logic for managing Admins
 * @help        :: See http://links.sailsjs.org/docs/controllers
 */

module.exports = {
  create: function (req, res, next) {
    sails.services.passport.protocols.local.register(req.body, function (err, admin) {
      if (err) return next(err);

      res.ok(admin);
    });
  },

  me: function (req, res) {
    res.ok(req.admin);
  }
};

