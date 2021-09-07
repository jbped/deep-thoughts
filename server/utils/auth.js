const jwt = require('jsonwebtoken');

const secret = 'superawesomeveryunknownsecretysecret';
const expiration = '2h';

module.exports = {
    signToken: function ({ username, email, _id }) {
        const payload = { username, email, _id };

        return jwt.sign({ data: payload }, secret, { expiresIn: expiration });
    },
    authMiddleware: function({ req }) {
        // different methods of the token being received.
        let token = req.body.token || req.query.token || req.headers.authorization;

        // separates the token from the bearer
        if(req.headers.authorization) {
            token = token
                .split(' ')
                .pop()
                .trim();
        }

        // return req if no token
        if(!token) {
            return req;
        }

        try {
            // decode and attach user data to req obj
            const { data } = jwt.verify(token, secret, { maxAge: expiration });
            req.user = data;
        } catch { console.log('Invalid token')}

        return req;
    }
}