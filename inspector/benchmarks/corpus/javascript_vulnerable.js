const crypto = require("crypto");

const legacyKey = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

const weakHash = crypto.createHash("md5").update("payload").digest();

module.exports = { legacyKey, weakHash };
