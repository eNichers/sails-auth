var assert = require('assert');
var request = require('supertest');
var _ = require('lodash');

describe('Employee Controller', function () {

  before(function (done) {
    request(sails.hooks.http.app)
      .post('/register')
      .send({
        email: 'me@mocha.test',
        password: 'admin1234'
      })
      .expect(200)
      .end(function (err) {
        done(err);
      });
  });

  describe('#me()', function () {
    it('should return Employee for this authenticated session', function (done) {
        var agent = request.agent(sails.hooks.http.app);

        agent
          .get('/employee/me')
          .auth('me@mocha.test', 'admin1234')
          .expect(200)
          .end(function (err, res) {
            var employee = res.body;
            assert(_.isObject(employee));
            assert.equal(employee.email, 'me@mocha.test');
            done(err);
          });
    });
  });

  describe('#create()', function () {

    describe('http request', function () {

      it('should be able to create new employee', function (done) {

        request(sails.hooks.http.app)
            .post('/register')
            .send({
              email: 'new.employee@email.com',
              password: 'admin1234'
            })
            .expect(200)
            .end(function (err) {
              done(err);
            });

      });

      it('should return error if employee already exists', function (done) {

        request(sails.hooks.http.app)
            .post('/register')
            .send({
              email: 'new.employee@email.com',
              password: 'admin1234'
            })
            .expect(400)
            .end(function (err) {
              done(err);
            });

      });

    });

    describe('socket request', function () {

      it('should be able to create new employee', function (done) {

        io.socket.post('/register', { email: 'new.socketemployee@email.com', password: 'admin1234' }, function (data, jwres) {

          assert.equal(jwres.statusCode, 200);
          done();

        });

      });

      it('should return error if employee already exists', function (done) {

        io.socket.post('/register', { email: 'new.socketemployee@email.com', password: 'admin1234' }, function (data, jwres) {

          assert.equal(jwres.statusCode, 400);
          done();

        });

      });

    });

  });

  describe('#findOne()', function () {

    describe('http request', function () {

      var employeeId;

      it('should find employee if they have been authenticated', function (done) {

        var agent = request.agent(sails.hooks.http.app);

        agent
            .post('/auth/local')
            .send({
              identifier: 'existing.employee@email.com',
              password: 'admin1234'
            })
            .expect(200, function (err, res) {

              if (err)
                return done(err);

              employeeId = res.body.id;

              agent
                  .get('/employee/' + employeeId)
                  .expect(200)
                  .end(function (err) {
                    done(err);
                  });
            });

      });

      it('should not find employee if they have logged out', function (done) {

        var agent = request.agent(sails.hooks.http.app);

        agent
            .get('/logout')
            .expect(302, function (err, res) {

              if (err)
                return done(err);

              agent
                  .get('/employee/' + employeeId)
                  .expect(403)
                  .end(function (err) {
                    done(err);
                  });
            });

      });

    });

    describe('socket request', function () {

      var employeeId;

      it('should find employee if they have been authenticated', function (done) {

        io.socket.post('/auth/local', { identifier: 'existing.employee@email.com', password: 'admin1234' }, function (data, jwres) {

          assert.equal(jwres.statusCode, 200);

          employeeId = data.id;

          io.socket.get('/employee/' + employeeId, function(data, jwres) {

            assert.equal(jwres.statusCode, 200);

            done();

          });

        });

      });

      it('should not find employee if they have logged out', function (done) {

        io.socket.get('/logout', function (data, jwres) {

          assert.equal(jwres.statusCode, 200);

          io.socket.get('/employee/' + employeeId, function(data, jwres) {

            assert.equal(jwres.statusCode, 403);

            done();

          });

        });

      });

    });

  });

});
