const jwt = require('jsonwebtoken');

// set token secret and expiration date
const secret = 'mysecretsshhhhh';
const expiration = '2h';

module.exports = {
  // function for our authenticated routes
  authMiddleware: function ({ req, connection }, res, next) {
    let token;
    
    if (req) {
      // allows token to be sent via  req.query or headers
      token = req.query.token || req.headers.authorization;
  
      // ["Bearer", "<tokenvalue>"]
      if (req.headers.authorization) {
        token = token.split(' ').pop().trim();
      }
    } else if (connection) {
      // allows token to be sent via connectionParams
      token = connection.context.Authorization;
    }

    if (!token) {
      return res.status(400).json({ message: 'You have no token!' });
    }

    try {
      // verify token and get user data out of it
      const { data } = jwt.verify(token, secret, { maxAge: expiration });
      req.user = data;
    } catch {
      console.log('Invalid token');
      return res.status(400).json({ message: 'invalid token!' });
    }

    // add the user data to the context
    if (req) {
      req.context = {
        user: req.user,
      };
    } else if (connection) {
      connection.context = {
        user: req.user,
      };
    }

    // send to next endpoint
    next();
  },
  signToken: function ({ username, email, _id }) {
    const payload = { username, email, _id };

    return jwt.sign({ data: payload }, secret, { expiresIn: expiration });
  },
};