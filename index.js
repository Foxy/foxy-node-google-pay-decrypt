const crypto = require('crypto');
const ECKey = require('ec-key');

const SENDER_ID = 'Google';
const PROTOCOL_VERSION = 'ECv2';
const CURVE = 'prime256v1';
const SALT = Buffer.from(new Array(32).fill(0));
const ALGORITHM = 'sha256';
const KEY_SIZE = 64;

class GooglePaymentToken {
    constructor (rootSigningKeys, gatewayId, privateKey) {
        if (!Array.isArray(rootSigningKeys)) {
            throw new Error('rootSigningKeys must be an array');
        }
        const currentTime = new Date();
        this.rootSigningKeys = rootSigningKeys.filter((key) => key.protocolVersion == PROTOCOL_VERSION && new Date(Number(key.keyExpiration)) > currentTime);

        if (this.rootSigningKeys.length == 0) {
            throw new Error(`At least one root signing key must be ${PROTOCOL_VERSION}-signed and have a valid expiration date.`);
        }
        this.gatewayId = gatewayId;
        this.privateKey = new ECKey(privateKey, 'pem');
    }

    decrypt (payload) {
        this.verifySignatures(payload);
        const signedMessage = JSON.parse(payload.signedMessage);
        const publicKey = new ECKey({
            curve: CURVE,
            publicKey: signedMessage.ephemeralPublicKey
        });
        /*
            Computing sharedSecret using ephemeralPublicKey and the given secret key
            More info: https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#decrypt-token
        */
        const sharedSecret = this.privateKey.computeSecret(publicKey);
        /*
            Generating 512 bit long (64 byte long) sharedKey using ephemeralPublicKey and the shared secret from the previous step
            More info: https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#decrypt-token
        */
        const sharedKey = Buffer.from(crypto.hkdfSync(ALGORITHM, Buffer.concat([Buffer.from(signedMessage.ephemeralPublicKey, 'base64'), sharedSecret]), SALT, Buffer.from(SENDER_ID), KEY_SIZE));
        /*
            Splitting the shared key to get two 256 bit long keys
            More info: https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#decrypt-token
        */
        const symmetricEncryptionKey = sharedKey.slice(0, KEY_SIZE/2);
        const macKey = sharedKey.slice(KEY_SIZE/2);
        const encryptedMessage = Buffer.from(signedMessage.encryptedMessage, 'base64');
        const tag = Buffer.from(signedMessage.tag, 'base64');
        const createdTag = crypto.createHmac(ALGORITHM, macKey);
        createdTag.update(encryptedMessage);

        if (tag.compare(createdTag.digest()) != 0) {
            throw Error('tag field is not valid!');
        }
        const decipher = crypto.createDecipheriv('aes-256-ctr', symmetricEncryptionKey, Buffer.alloc(16));
        let decrypted = decipher.update(encryptedMessage);
        decrypted += decipher.final('utf-8');

        let decrypted_data = {};

        try {
            decrypted_data = JSON.parse(decrypted);
        } catch (e) {
            throw Error(`Decoded payload is not a valid JSON string: ${decrypted}`);
        }

        if (this.checkKeyExpirationDate(decrypted_data['messageExpiration'])) {
            throw Error('The payment token has expired');
        }

        return decrypted_data;
    }

    verifySignatures (payload) {
        this.verifyIntermediateSignature(payload);
        const signedKey = this.validateIntermediateSigningKey(payload);
        this.verifyMessageSignature(signedKey, payload);
    }

    checkKeyExpirationDate(expirationDateString) {
        const currentDate = new Date();
        const expirationDate = new Date(Number.parseInt(expirationDateString));

        return currentDate > expirationDate;
    }

    validateIntermediateSigningKey(payload) {
        if (this.checkKeyExpirationDate(JSON.parse(payload.intermediateSigningKey.signedKey).keyExpiration)) {
            throw Error('Intermediate signature key has expired');
        }
        return JSON.parse(payload.intermediateSigningKey.signedKey);
    }

    generateSignedData(singedData, useRecepientId = false) {
        /*
            Generating buffer for checking signatures by contating byte lenght of each component. The length of the static components need to be in little-endian format.
            For examples check https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#decrypt-token
        */
        const senderLength = Buffer.alloc(4);
        const protocolLength = Buffer.alloc(4);
        const signedKeyLength = Buffer.alloc(4);
        senderLength.writeUint32LE(SENDER_ID.length);
        protocolLength.writeUint32LE(PROTOCOL_VERSION.length);
        signedKeyLength.writeUint32LE(singedData.length);

        if (useRecepientId) {
            const gatewayId = `gateway:${this.gatewayId}`;
            const gatewayIdLength = Buffer.alloc(4);
            gatewayIdLength.writeUint32LE(gatewayId.length);

            return Buffer.concat([senderLength, Buffer.from(SENDER_ID, 'utf8'), gatewayIdLength, Buffer.from(gatewayId, 'utf8'), protocolLength, Buffer.from(PROTOCOL_VERSION, 'utf8'), signedKeyLength, Buffer.from(singedData, 'utf8')]);
        }

        return Buffer.concat([senderLength, Buffer.from(SENDER_ID, 'utf8'), protocolLength, Buffer.from(PROTOCOL_VERSION, 'utf8'), signedKeyLength, Buffer.from(singedData, 'utf8')]);
    }

    verifyIntermediateSignature (payload) {
        let validSignature = false;
        const intermediateSigningKey = payload.intermediateSigningKey;
        const intermediateSignatureString = this.generateSignedData(intermediateSigningKey.signedKey);

        this.rootSigningKeys.forEach(key => {
            const publicKey = crypto.createPublicKey({
                key: key.keyValue,
                format: 'der',
                type: 'spki',
                encoding: 'base64'
            });
            const verify = crypto.createVerify(ALGORITHM);
            verify.write(intermediateSignatureString);
            verify.end();

            intermediateSigningKey.signatures.forEach((signature) => {
                if (verify.verify(publicKey, signature, 'base64')) {
                    validSignature = true;
                }
            });
        });

        if (!validSignature) {
            throw Error('Could not verify intermediate signing key signature');
        }
    }

    verifyMessageSignature (signedKey, payload) {
        const publicKey = crypto.createPublicKey({
            key: signedKey.keyValue,
            format: 'der',
            type: 'spki',
            encoding: 'base64'
        });
        const signedData = this.generateSignedData(payload.signedMessage, true);
        const verify = crypto.createVerify(ALGORITHM);
        verify.write(signedData);
        verify.end();

        if (!verify.verify(publicKey, payload.signature, 'base64')) {
            throw Error('Could not verify message signature!');
        }
    }
}

module.exports = GooglePaymentToken;
