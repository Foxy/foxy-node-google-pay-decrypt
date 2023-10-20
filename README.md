# Google Pay Decrypt

This package allows you to decrypt a token received from Google Pay.

This works in `node` and not on a browser, as it requires the built-in `crypto` package and secret keys (`.pem` files), which should never exist on the client anyway.

The decryption methodology of this package is largely taken from the [Python Google Pay Token Decryption](https://github.com/yoyowallet/google-pay-token-decryption).

## Getting Started

```sh
npm i --save foxy-node-google-pay-decrypt
```

In order to decrypt the token, you will need the `.pem` file, the gateway id, and Google signing keys.
In order to get the Google signing keys you will have to fetch them from one of the two URLs. You have the sandbox URL https://payments.developers.google.com/paymentmethodtoken/test/keys.json or the production URL https://payments.developers.google.com/paymentmethodtoken/keys.json.


And a key (`privatePem.pem`) that looks something like this:

```
-----BEGIN EC PRIVATE KEY-----
7G3PLjvRkmLcZd1H4CX6XbE7nrMrUU4tJc1sO5Cs0n4gnncYbJoTJXLIYN3o4FXL
9T33p5TtiTh4pkBzsj8zRHWeFrJoRaitZmnVBAL5u2v9f98d8mwN4uhP5bsS7lwa
GQPYeVaMGHaWQctQbQx26D1C5oGcPir3LP==
-----END EC PRIVATE KEY-----

```

## Usage

The token that you get from Google Pay will look something like this:
```js
{
    "signature": "MEYCIQD...<a lot more data>...9GwgIhALJ/5PrBogdma+aft/ZEU0UYklTEteJYrkbphfeg4FpW",
    "intermediateSigningKey": {
        "signedKey": "{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0D...<a lot more data>...Qn1GLn9rh33FVdUadzkZc2b4oTCKA\\u003d\\u003d\",\"keyExpiration\":\"1698424300849\"}",
        "signatures": [
            "MEQCIAmx8FHGQs9jRTlacoUSD7T969Vz77+...<a lot more data>...mWh5f8qds+K6e+kL4wxdi/FswUQ=="
        ]
    },
    "protocolVersion": "ECv2",
    "signedMessage": "{\"encryptedMessage\":\"zA3SNtOdi...<a lot more data>...FhfKXNjcxz1LkEvTFKir8NFyoLf+Gbxcf7u3eNllgGwiTbjm1FlJAZHHy6WiNg\\u003d\",\"ephemeralPublicKey\":\"BDDaWyJv0u9DdWWosdYI...<a lot more data>...D8qntQO/3jhrMemajE4pI\\u003d\",\"tag\":\"lfEFA5...<a lot more data>...2bRGyS+yESzrqQ0\\u003d\"}"
}
```

To decrypt the token, import the `.pem` file, fetch the Google singing keys and create a new `GooglePaymentToken` with the token from Google Pay. Then decrypt using the keys.

```js
const use_sandbox = false;
const rootSigningKeysUrl = use_sandbox ? 'https://payments.developers.google.com/paymentmethodtoken/test/keys.json' : 'https://payments.developers.google.com/paymentmethodtoken/keys.json';
fetch(rootSigningKeysUrl).then(async (result) => {
    const key = file.readFileSync('/path/to/key.pem');
    const rootSigningKeys = await result.json();
    const token = new GooglePaymentToken(rootSigningKeys.keys, 'gatewayId', key);
    const decryptedToken = token.decrypt(data);
    console.log(decryptedToken);
}).catch((err) => {
    console.log(err);
});
```

The `decrypted` value at this point should look something like this:

```js
{
  messageExpiration: '169832356723',
  messageId: 'GQPYeVaMGHaWQctQbQx26D1C5oGcPir3LPGQPYeVaMGHaWQctQbQx26D1C5oGcPir3LPGQPYeVaMGHaWQctQbQx26D1C5oGcPir3LPGQPYeVaMGHaWQctQbQx26D1C5oGcPir3LPGQPYeVaMGHaWQctQbQx26D1C5oGcPir3LP',
  paymentMethod: 'CARD',
  paymentMethodDetails: {
    expirationYear: 2028,
    expirationMonth: 8,
    pan: '4111111111111111',
    authMethod: 'PAN_ONLY'
  }
}
```

You can then use those decrypted values with your payment processor of choice (Stripe, Braintree, et al) to process payments from Google Pay. 
