var assert = require('assert');
var request = require('supertest');
var _ = require('lodash');

describe('Admin Controller', function () {

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
    it('should return Admin for this authenticated session', function (done) {
        var agent = request.agent(sails.hooks.http.app);

        agent
          .get('/admin/me')
          .auth('me@mocha.test', 'admin1234')
          .expect(200)
          .end(function (err, res) {
            var admin = res.body;
            assert(_.isObject(admin));
            assert.equal(admin.email, 'me@mocha.test');
            done(err);
          });
    });
  });

  describe('#create()', function () {

    describe('http request', function () {

      it('should be able to create new admin', function (done) {

        request(sails.hooks.http.app)
            .post('/register')
            .send({
              email: 'new.admin@email.com',
              password: 'admin1234'
            })
            .expect(200)
            .end(function (err) {
              done(err);
            });

      });

      it('should return error if admin already exists', function (done) {

        request(sails.hooks.http.app)
            .post('/register')
            .send({
              email: 'new.admin@email.com',
              password: 'admin1234'
            })
            .expect(400)
            .end(function (err) {
              done(err);
            });

      });

    });

    describe('socket request', function () {

      it('should be able to create new admin', function (done) {

        io.socket.post('/register', { email: 'new.socketadmin@email.com', password: 'admin1234' }, function (data, jwres) {

          assert.equal(jwres.statusCode, 200);
          done();

        });

      });

      it('should return error if admin already exists', function (done) {

        io.socket.post('/register', { email: 'new.socketadmin@email.com', password: 'admin1234' }, function (data, jwres) {

          assert.equal(jwres.statusCode, 400);
          done();

        });

      });

    });

  });

  describe('#findOne()', function () {

    describe('http request', function () {

      var adminId;

      it('should find admin if they have been authenticated', function (done) {

        var agent = request.agent(sails.hooks.http.app);

        agent
            .post('/auth/local')
            .send({
              identifier: 'existing.admin@email.com',
              password: 'admin1234'
            })
            .expect(200, function (err, res) {

              if (err)
                return done(err);

              adminId = res.body.id;

              agent
                  .get('/admin/' + adminId)
                  .expect(200)
                  .end(function (err) {
                    done(err);
                  });
            });

      });

      it('should not find admin if they have logged out', function (done) {

        var agent = request.agent(sails.hooks.http.app);

        agent
            .get('/logout')
            .expect(302, function (err, res) {

              if (err)
                return done(err);

              agent
                  .get('/admin/' + adminId)
                  .expect(403)
                  .end(function (err) {
                    done(err);
                  });
            });

      });

    });

    describe('socket request', function () {

      var adminId;

      it('should find admin if they have been authenticated', function (done) {

        io.socket.post('/auth/local', { identifier: 'existing.admin@email.com', password: 'admin1234' }, function (data, jwres) {

          assert.equal(jwres.statusCode, 200);

          adminId = data.id;

          io.socket.get('/admin/' + adminId, function(data, jwres) {

            assert.equal(jwres.statusCode, 200);

            done();

          });

        });

      });

      it('should not find admin if they have logged out', function (done) {

        io.socket.get('/logout', function (data, jwres) {

          assert.equal(jwres.statusCode, 200);

          io.socket.get('/admin/' + adminId, function(data, jwres) {

            assert.equal(jwres.statusCode, 403);

            done();

          });

        });

      });

    });

  });

});
