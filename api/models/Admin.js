var _ = require('lodash');
var crypto = require('crypto');
var Promise = require("bluebird");

/** @module Admin */
module.exports = {
  attributes: {
    adminName: {
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
      via: 'admin'
    },

    getGravatarUrl: function () {
      var md5 = crypto.createHash('md5');
      md5.update(this.email || '');
      return 'https://gravatar.com/avatar/'+ md5.digest('hex');
    },

    toJSON: function () {
      var admin = this.toObject();
      delete admin.password;
      admin.gravatarUrl = this.getGravatarUrl();
      return admin;
    }
  },

  beforeCreate: function (admin, next) {
    if (_.isEmpty(admin.adminName)) {
      admin.adminName = admin.email;
    }
    next();
  },

  /**
   * Register a new Admin with a passport
   */
  register: function (admin) {
    return new Promise(function (resolve, reject) {
      sails.services.passport.protocols.local.createAdmin(admin, function (error, created) {
        if (error) return reject(error);

        resolve(created);
      });
    });
  }
};
