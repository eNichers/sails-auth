var _ = require('lodash');

/**
 * sessionAuth
 *
 * @module      :: Policy
 * @description :: Simple policy to allow any authenticated employee
 * @docs        :: http://sailsjs.org/#!documentation/policies
 */
module.exports = function(req, res, next) {
  // Employee is allowed, proceed to the next policy, 
  // or if this is the last policy, the controller
  if (req.session.authenticated) {
    return next();
  }

  res.status(403).json({ error: 'You are not permitted to perform this action.' });
};
