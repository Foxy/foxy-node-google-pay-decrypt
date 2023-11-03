import { createVerify, createPublicKey, createDecipheriv, createHmac, hkdfSync, Hmac, Decipher, KeyObject, Verify } from "crypto";
import { IntermediateSigningKey, GooglePayPayload, GoogleSignedMessage, GoogleSignedKey, GoogleRootSigningKeys, DecryptedData } from './types';
import { SENDER_ID, PROTOCOL_VERSION, CURVE, SALT, ALGORITHM, KEY_SIZE } from './consts';
import ECKey from 'ec-key';

export default class GooglePaymentToken {
    private rootSigningKeys: Array<GoogleRootSigningKeys>;
    private gatewayId: string;
    private privateKey: ECKey;

    constructor (rootSigningKeys: Array<GoogleRootSigningKeys>, gatewayId: string, privateKeyRaw: string) {
        const currentTime = new Date();
        this.rootSigningKeys = rootSigningKeys.filter((key) => key.protocolVersion == PROTOCOL_VERSION && new Date(Number(key.keyExpiration)) > currentTime);

        if (this.rootSigningKeys.length == 0) {
            throw new Error(`At least one root signing key must be ${PROTOCOL_VERSION}-signed and have a valid expiration date.`);
        }
        this.gatewayId = gatewayId;
        this.privateKey = new ECKey(privateKeyRaw, 'pem');
    }

    decrypt (payload: GooglePayPayload): Object {
        this.verifySignatures(payload);
        const signedMessage: GoogleSignedMessage = JSON.parse(payload.signedMessage);
        const publicKey: ECKey = new ECKey({
            curve: CURVE,
            publicKey: signedMessage.ephemeralPublicKey
        });
        /*
            Computing sharedSecret using ephemeralPublicKey and the given secret key
            More info: https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#decrypt-token
        */
        const sharedSecret: Buffer = this.privateKey.computeSecret(publicKey);
        /*
            Generating 512 bit long (64 byte long) sharedKey using ephemeralPublicKey and the shared secret from the previous step
            More info: https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#decrypt-token
        */
        const sharedKey: Buffer = Buffer.from(hkdfSync(ALGORITHM, Buffer.concat([Buffer.from(signedMessage.ephemeralPublicKey, 'base64'), sharedSecret]), SALT, Buffer.from(SENDER_ID), KEY_SIZE));
        /*
            Splitting the shared key to get two 256 bit long keys
            More info: https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#decrypt-token
        */
        const symmetricEncryptionKey: Buffer = sharedKey.subarray(0, KEY_SIZE/2);
        const macKey: Buffer = sharedKey.subarray(KEY_SIZE/2);
        const encryptedMessage: Buffer = Buffer.from(signedMessage.encryptedMessage, 'base64');
        const tag: Buffer = Buffer.from(signedMessage.tag, 'base64');
        const createdTag: Hmac = createHmac(ALGORITHM, macKey);
        createdTag.update(encryptedMessage);

        if (tag.compare(createdTag.digest()) != 0) {
            throw Error('tag field is not valid!');
        }
        const decipher: Decipher = createDecipheriv('aes-256-ctr', symmetricEncryptionKey, Buffer.alloc(16));
        let decrypted: string = decipher.update(encryptedMessage).toString();
        decrypted += decipher.final('utf-8');


        try {
            let decrypted_data: DecryptedData = JSON.parse(decrypted);

            if (this.checkKeyExpirationDate(decrypted_data.messageExpiration)) {
                throw Error('The payment token has expired');
            }
            return decrypted_data;
        } catch (e) {
            throw Error(`Decoded payload is not a valid JSON string: ${decrypted}`);
        }
    }

    private verifySignatures (payload: GooglePayPayload): void {
        this.verifyIntermediateSignature(payload);
        const signedKey: GoogleSignedKey = this.validateIntermediateSigningKey(payload);
        this.verifyMessageSignature(signedKey, payload);
    }

    private checkKeyExpirationDate(expirationDateString: string): boolean {
        const currentDate = new Date();
        const expirationDate = new Date(Number.parseInt(expirationDateString));

        return currentDate > expirationDate;
    }

    private validateIntermediateSigningKey(payload: GooglePayPayload): GoogleSignedKey {
        if (this.checkKeyExpirationDate(JSON.parse(payload.intermediateSigningKey.signedKey).keyExpiration)) {
            throw Error('Intermediate signature key has expired');
        }
        return JSON.parse(payload.intermediateSigningKey.signedKey);
    }

    private generateSignedData(singedData: string, useRecepientId: boolean = false): Buffer {
        /*
            Generating buffer for checking signatures by contating byte lenght of each component. The length of the static components need to be in little-endian format.
            For examples check https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#decrypt-token
        */
        const senderLength: Buffer = Buffer.alloc(4);
        const protocolLength: Buffer = Buffer.alloc(4);
        const signedKeyLength: Buffer = Buffer.alloc(4);
        senderLength.writeUint32LE(SENDER_ID.length);
        protocolLength.writeUint32LE(PROTOCOL_VERSION.length);
        signedKeyLength.writeUint32LE(singedData.length);

        if (useRecepientId) {
            const gatewayId: string = `gateway:${this.gatewayId}`;
            const gatewayIdLength: Buffer = Buffer.alloc(4);
            gatewayIdLength.writeUint32LE(gatewayId.length);

            return Buffer.concat([senderLength, Buffer.from(SENDER_ID, 'utf8'), gatewayIdLength, Buffer.from(gatewayId, 'utf8'), protocolLength, Buffer.from(PROTOCOL_VERSION, 'utf8'), signedKeyLength, Buffer.from(singedData, 'utf8')]);
        }

        return Buffer.concat([senderLength, Buffer.from(SENDER_ID, 'utf8'), protocolLength, Buffer.from(PROTOCOL_VERSION, 'utf8'), signedKeyLength, Buffer.from(singedData, 'utf8')]);
    }

    private verifyIntermediateSignature (payload: GooglePayPayload) {
        let validSignature: boolean = false;
        const intermediateSigningKey: IntermediateSigningKey = payload.intermediateSigningKey;
        const intermediateSignatureBuffer: Buffer = this.generateSignedData(intermediateSigningKey.signedKey);

        this.rootSigningKeys.forEach(key => {
            const publicKey: KeyObject = createPublicKey({
                key: key.keyValue,
                format: 'der',
                type: 'spki',
                encoding: 'base64'
            });
            const verify: Verify = createVerify(ALGORITHM);
            verify.write(intermediateSignatureBuffer);
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

    private verifyMessageSignature (signedKey: GoogleSignedKey, payload: GooglePayPayload) {
        const publicKey: KeyObject = createPublicKey({
            key: signedKey.keyValue,
            format: 'der',
            type: 'spki',
            encoding: 'base64'
        });
        const signedData: Buffer = this.generateSignedData(payload.signedMessage, true);
        const verify: Verify = createVerify(ALGORITHM);
        verify.write(signedData);
        verify.end();

        if (!verify.verify(publicKey, payload.signature, 'base64')) {
            throw Error('Could not verify message signature!');
        }
    }
}
