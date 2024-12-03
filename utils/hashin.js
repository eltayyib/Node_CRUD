const bcrypt = require('bcryptjs');
const {createHmac} = require('crypto');

exports.doHash = (value, saltValue) => {
    const result = bcrypt.hashSync(value, saltValue);
    return result;
};

exports.doHashValidation = (value, hashedValue) => {
    const result = bcrypt.compareSync(value, hashedValue);
    return result;
};

exports.hmacProcess = (value, key) => {
        const result = createHmac('sha256', key).update(value).digest('hex')
        return result;
}