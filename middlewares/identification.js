const jwt = require('jsonwebtoken');

exports.identifier = (req, res, next) => {
    let token;

    if (req.headers.client === 'not browser') {
        token = req.headers.authorization; 
    } else {
        token = req.cookies['Authorization'];
    }

    if (!token) {
        return res.status(403).json({ success: false, message: 'Unauthorized: No token provided' });
    }

    try {
        const userToken = token.startsWith('Bearer ') ? token.split(' ')[1] : token; 
        const jwtVerified = jwt.verify(userToken, process.env.TOKEN_SECRET);

        req.user = jwtVerified;
        next();
    } catch (error) {
        console.error('Token verification failed:', error.message);
        return res.status(403).json({ success: false, message: 'Unauthorized: Invalid token' });
    }
};
