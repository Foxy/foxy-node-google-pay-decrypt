import {
  createDecipheriv,
  createPublicKey,
  createVerify,
  createHmac,
  hkdfSync,
} from "crypto";

import type {
  GoogleRootSigningKeys,
  GoogleSignedMessage,
  GooglePayPayload,
  GoogleSignedKey,
  DecryptedData,
} from "./types.d.ts";

import ECKey from "ec-key";

/**
 * This package allows you to decrypt a token received from Google Pay. This works in node and not in a browser,
 * as it requires the built-in `crypto` package and secret keys (`.pem` files), which should never
 * exist on the client anyway. The decryption methodology of this package is largely taken from
 * the [Python Google Pay Token Decryption](https://github.com/yoyowallet/google-pay-token-decryption).
 */
export default class GooglePaymentToken {
  static PROTOCOL_VERSION = "ECv2";
  static SENDER_ID = "Google";
  static ALGORITHM = "sha256";
  static KEY_SIZE = 64;
  static CURVE = "prime256v1";
  static SALT = Buffer.from(new Array(32).fill(0));

  private __rootSigningKeys: GoogleRootSigningKeys[];
  private __privateKey: ECKey;
  private __gatewayId: string;

  constructor(
    rootSigningKeys: GoogleRootSigningKeys[],
    gatewayId: string,
    privateKeyRaw: string
  ) {
    const now = Date.now();
    const validKeys = rootSigningKeys.filter((key) => {
      return (
        key.protocolVersion === GooglePaymentToken.PROTOCOL_VERSION &&
        key.keyExpiration &&
        parseInt(key.keyExpiration) > now
      );
    });

    if (validKeys.length === 0) {
      const message = `At least one root signing key must be ${GooglePaymentToken.PROTOCOL_VERSION}-signed and have a valid expiration date.`;
      throw new Error(message);
    }

    this.__rootSigningKeys = validKeys;
    this.__privateKey = new ECKey(privateKeyRaw, "pem");
    this.__gatewayId = gatewayId;
  }

  decrypt(payload: GooglePayPayload): DecryptedData {
    this.__verifyIntermediateSignature(
      payload.intermediateSigningKey.signatures,
      payload.intermediateSigningKey.signedKey
    );

    const signedKey = this.__validateIntermediateSigningKey(payload);
    this.__verifyMessageSignature(signedKey.keyValue, payload);

    const signedMessage = JSON.parse(
      payload.signedMessage
    ) as GoogleSignedMessage;

    const publicKey = new ECKey({
      publicKey: signedMessage.ephemeralPublicKey,
      curve: GooglePaymentToken.CURVE,
    });

    // Computing sharedSecret using ephemeralPublicKey and the given secret key
    // More info: https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#decrypt-token
    const sharedSecret = this.__privateKey.computeSecret(publicKey);

    // Generating 512 bit long (64 byte long) sharedKey using ephemeralPublicKey and the shared secret from the previous step
    // More info: https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#decrypt-token
    const sharedKey = Buffer.from(
      hkdfSync(
        GooglePaymentToken.ALGORITHM,
        Buffer.concat([
          Buffer.from(signedMessage.ephemeralPublicKey, "base64"),
          sharedSecret,
        ]),
        GooglePaymentToken.SALT,
        Buffer.from(GooglePaymentToken.SENDER_ID),
        GooglePaymentToken.KEY_SIZE
      )
    );

    // Splitting the shared key to get two 256 bit long keys
    // More info: https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#decrypt-token
    const subarrayEnd = GooglePaymentToken.KEY_SIZE / 2;
    const sencKey = sharedKey.subarray(0, subarrayEnd);
    const macKey = sharedKey.subarray(subarrayEnd);
    const createdTag = createHmac(GooglePaymentToken.ALGORITHM, macKey);
    const message = Buffer.from(signedMessage.encryptedMessage, "base64");
    const tag = Buffer.from(signedMessage.tag, "base64");
    createdTag.update(message);

    if (tag.compare(createdTag.digest()) !== 0) {
      throw Error("tag field is not valid!");
    }

    const iv = createDecipheriv("aes-256-ctr", sencKey, Buffer.alloc(16));
    const decrypted = `${iv.update(message)}${iv.final("utf-8")}`;
    let decryptedData: DecryptedData;

    try {
      decryptedData = JSON.parse(decrypted) as DecryptedData;

    } catch {
      throw Error(`Decoded payload is not a valid JSON string: ${decrypted}`);
    }

    if (Date.now() > parseInt(decryptedData.messageExpiration)) {
      throw Error("The payment token has expired");
    }

    return decryptedData;
  }

  private __validateIntermediateSigningKey(payload: GooglePayPayload) {
    const rawSignedKey = payload.intermediateSigningKey.signedKey;
    const signedKey = JSON.parse(rawSignedKey) as GoogleSignedKey;

    if (Date.now() > parseInt(signedKey.keyExpiration)) {
      throw Error("Intermediate signature key has expired");
    }

    return signedKey;
  }

  private __generateSignedData(singedData: string, useRecepientId = false) {
    // Generating buffer for checking signatures by contating byte lenght of each component. The length of the static components need to be in little-endian format.
    // For examples check https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#decrypt-token

    const senderLength = Buffer.alloc(4);
    const protocolLength = Buffer.alloc(4);
    const signedKeyLength = Buffer.alloc(4);

    senderLength.writeUint32LE(GooglePaymentToken.SENDER_ID.length);
    protocolLength.writeUint32LE(GooglePaymentToken.PROTOCOL_VERSION.length);
    signedKeyLength.writeUint32LE(singedData.length);

    if (useRecepientId) {
      const gatewayId = `gateway:${this.__gatewayId}`;
      const gatewayIdLength = Buffer.alloc(4);
      gatewayIdLength.writeUint32LE(gatewayId.length);

      return Buffer.concat([
        senderLength,
        Buffer.from(GooglePaymentToken.SENDER_ID, "utf8"),
        gatewayIdLength,
        Buffer.from(gatewayId, "utf8"),
        protocolLength,
        Buffer.from(GooglePaymentToken.PROTOCOL_VERSION, "utf8"),
        signedKeyLength,
        Buffer.from(singedData, "utf8"),
      ]);
    }

    return Buffer.concat([
      senderLength,
      Buffer.from(GooglePaymentToken.SENDER_ID, "utf8"),
      protocolLength,
      Buffer.from(GooglePaymentToken.PROTOCOL_VERSION, "utf8"),
      signedKeyLength,
      Buffer.from(singedData, "utf8"),
    ]);
  }

  private __verifyIntermediateSignature(signatures: string[], key: string) {
    const intermediateSignatureBuffer = this.__generateSignedData(key);

    for (const rootSigningKey of this.__rootSigningKeys) {
      const publicKey = createPublicKey({
        encoding: "base64",
        format: "der",
        type: "spki",
        key: rootSigningKey.keyValue,
      });

      const verifier = createVerify(GooglePaymentToken.ALGORITHM);
      verifier.write(intermediateSignatureBuffer);
      verifier.end();

      for (const signature of signatures) {
        if (!verifier.verify(publicKey, signature, "base64")) {
          throw Error("Could not verify intermediate signing key signature");
        }
      }
    }
  }

  private __verifyMessageSignature(key: string, payload: GooglePayPayload) {
    const publicKey = createPublicKey({
      encoding: "base64",
      format: "der",
      type: "spki",
      key,
    });

    const signedData = this.__generateSignedData(payload.signedMessage, true);
    const verifier = createVerify(GooglePaymentToken.ALGORITHM);
    verifier.write(signedData);
    verifier.end();

    if (!verifier.verify(publicKey, payload.signature, "base64")) {
      throw Error("Could not verify message signature!");
    }
  }
}
