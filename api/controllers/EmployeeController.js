/**
 * EmployeeController
 *
 * @description :: Server-side logic for managing Employees
 * @help        :: See http://links.sailsjs.org/docs/controllers
 */

module.exports = {
  create: function (req, res, next) {
    sails.services.passport.protocols.local.register(req.body, function (err, employee) {
      if (err) return next(err);

      res.ok(employee);
    });
  },

  me: function (req, res) {
    res.ok(req.employee);
  }
};

