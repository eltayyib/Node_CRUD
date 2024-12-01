const bcrypt = require('bcryptjs');

exports.doHash = (value, saltValue) => {
    // 
    const result = bcrypt.hashSync(value, saltValue) // this is synchronous.
    return result;
};

exports.doHashValidation = (value, hashedValue) =>{
    const result = compare (value, hashedValue);
    return result;
}