"use strict";
exports.__esModule = true;
exports.GCM = void 0;
var crypto = require("crypto");
var ALGORITHM = 'aes-256-gcm';
var SALT_LENGTH = 16;
var IV_LENGTH = 12;
var TAG_LENGTH = 16;
var KEY_LENGTH = 32;
var ITERATION = 65535;
var ENCRYPTED_POSITION = SALT_LENGTH + IV_LENGTH;
var GCM = /** @class */ (function () {
    function GCM(secret) {
        this.secret = secret;
    }
    GCM.prototype.getKey = function (salt) {
        return crypto.pbkdf2Sync(this.secret, salt, ITERATION, KEY_LENGTH, 'sha512');
    };
    GCM.prototype.encrypt = function (plainText) {
        var salt = crypto.randomBytes(SALT_LENGTH);
        var iv = crypto.randomBytes(IV_LENGTH);
        var key = this.getKey(salt);
        var cipher = crypto.createCipheriv(ALGORITHM, key, iv);
        var encrypted = Buffer.concat([
            cipher.update(String(plainText), 'utf8'),
            cipher.final(),
        ]);
        var tag = cipher.getAuthTag();
        console.log([salt, iv, encrypted, tag], "data array");
        return Buffer.concat([salt, iv, encrypted, tag]).toString('base64');
    };
    GCM.prototype.decrypt = function (cipherText) {
        var stringValue = Buffer.from(String(cipherText), 'base64');
        var salt = stringValue.slice(0, SALT_LENGTH);
        var iv = stringValue.slice(SALT_LENGTH, ENCRYPTED_POSITION);
        var encrypted = stringValue.slice(ENCRYPTED_POSITION, stringValue.length - TAG_LENGTH);
        var tag = stringValue.slice(-TAG_LENGTH);
        var key = this.getKey(salt);
        var decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(tag);
        return decipher.update(encrypted) + decipher.final('utf8');
    };
    return GCM;
}());
exports.GCM = GCM;
var secretKey = 'whatuni';
var message = 'Prabhakaran';
var gcm = new GCM(secretKey);
// let encryptedValue = gcm.encrypt(message);
var decryptedvalue = gcm.decrypt("NUkdB3QvvywWeozvQhgxUNQHGTcJTZpYumlJJZxGCeCM/SfWD+TyzP+Dkuo7Znk84k54j0fw4g==");
console.table({
    // encryptedValue,
    decryptedvalue: decryptedvalue
});
