var localProtocol = require('./local');

module.exports = function (req, adminName, password, next) {
  sails.log('using basic auth strategy for admin', adminName, ', password', password);

  return localProtocol.login(req, adminName, password, next);
};
