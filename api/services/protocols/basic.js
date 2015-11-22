var localProtocol = require('./local');

module.exports = function (req, employeeName, password, next) {
  sails.log('using basic auth strategy for employee', employeeName, ', password', password);

  return localProtocol.login(req, employeeName, password, next);
};
