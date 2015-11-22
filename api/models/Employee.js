var _ = require('lodash');
var crypto = require('crypto');
var Promise = require("bluebird");

/** @module Employee */
module.exports = {
  attributes: {
    employeeName: {
      type: 'string',
      unique: true,
      index: true,
      notNull: true
    },
    email: {
      type: 'email',
      notNull: true,
      unique: true,
      index: true
    },
    passports: {
      collection: 'Passport',
      via: 'employee'
    },

    getGravatarUrl: function () {
      var md5 = crypto.createHash('md5');
      md5.update(this.email || '');
      return 'https://gravatar.com/avatar/'+ md5.digest('hex');
    },

    toJSON: function () {
      var employee = this.toObject();
      delete employee.password;
      employee.gravatarUrl = this.getGravatarUrl();
      return employee;
    }
  },

  beforeCreate: function (employee, next) {
    if (_.isEmpty(employee.employeeName)) {
      employee.employeeName = employee.email;
    }
    next();
  },

  /**
   * Register a new Employee with a passport
   */
  register: function (employee) {
    return new Promise(function (resolve, reject) {
      sails.services.passport.protocols.local.createEmployee(employee, function (error, created) {
        if (error) return reject(error);

        resolve(created);
      });
    });
  }
};
