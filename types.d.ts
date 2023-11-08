export type GoogleRootSigningKeys = {
  protocolVersion: string;
  keyExpiration?: string;
  keyValue: string;
};

export type GoogleSignedMessage = {
  ephemeralPublicKey: string;
  encryptedMessage: string;
  tag: string;
};

export type GooglePayPayload = {
  intermediateSigningKey: { signatures: string[]; signedKey: string };
  protocolVersion: string;
  signedMessage: string;
  signature: string;
};

export type GoogleSignedKey = {
  keyExpiration: string;
  keyValue: string;
};

export type DecryptedData = {
  paymentMethodDetails: {
    expirationMonth: number;
    expirationYear: number;
    eciIndicator?: string;
    authMethod: string;
    cryptogram?: string;
    pan: string;
  };
  messageExpiration: string;
  gatewayMerchantId?: string;
  paymentMethod: string;
  messageId: string;
};
