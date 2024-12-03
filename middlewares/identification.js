const jwt = require('jsonwebtoken');

exports.identifier = (req, res, next) => {
    let token;

    // Check if the token comes from the header or cookies
    if (req.headers.client === 'not browser') {
        token = req.headers.authorization; // Expecting 'Bearer <token>'
    } else {
        token = req.cookies['Authorization'];
    }

    if (!token) {
        return res.status(403).json({ success: false, message: 'Unauthorized: No token provided' });
    }

    try {
        const userToken = token.startsWith('Bearer ') ? token.split(' ')[1] : token; // Remove 'Bearer ' prefix if present
        const jwtVerified = jwt.verify(userToken, process.env.TOKEN_SECRET);

        // Attach the decoded token to the request object
        req.user = jwtVerified;

        // Proceed to the next middleware or route handler
        next();
    } catch (error) {
        console.error('Token verification failed:', error.message);
        return res.status(403).json({ success: false, message: 'Unauthorized: Invalid token' });
    }
};
