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
      custom: (value) => value != null
    },
    email: {
      type: 'email',
      isEmail: true,
      unique: true,
      // index: true
    },
    passports: {
      collection: 'Passport',
      via: 'admin'
    }
  },

  customToJSON: function() {
    const admin = _.clone(this)
    delete admin.password;

    const md5 = crypto.createHash('md5');
    md5.update(admin.email || '');
    admin.gravatarUrl = 'https://gravatar.com/avatar/'+ md5.digest('hex');

    return admin;
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
