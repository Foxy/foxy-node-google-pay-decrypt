export type IntermediateSigningKey = {
    signedKey: string,
    signatures: Array<string>,
};

export type GooglePayPayload = {
    protocolVersion: string,
    signature: string,
    signedMessage: string,
    intermediateSigningKey: IntermediateSigningKey,
};

export type GoogleSignedMessage = {
    encryptedMessage: string,
    ephemeralPublicKey: string,
    tag: string
};

export type GoogleSignedKey = {
    keyValue: string,
    keyExpiration: string
};

export type GoogleRootSigningKeys = {
    keyValue: string,
    protocolVersion: string,
    keyExpiration?: string
};

export type DecryptedData = {
    paymentMethod: string,
        paymentMethodDetails: {
            authMethod: string,
            pan: string,
            expirationMonth: number,
            expirationYear: number,
            cryptogram?: string,
            eciIndicator?: string
        },
    messageId: string,
    messageExpiration: string,
    gatewayMerchantId?: string
};