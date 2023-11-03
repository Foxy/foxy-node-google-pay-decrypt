declare module "ec-key" {
  import { ECDH, Sign, Verify } from "crypto";

  export default class ECKey {
    /** To create a random ECKey instance simply call the createECKey static method, optionally specifying a curve name (defaults to prime256v1). */
    static createECKey: (curve: string) => ECKey;

    constructor(value: string | Buffer, format: string);
    constructor(params: {
      curve?: string;
      kty?: string;
      crv?: string;
      x?: string;
      y?: string;
      kid?: string;
      publicKey?: string;
      privateKey?: string;
    });

    /** The EC key curve name in OpenSSL format (e.g. prime256v1) */
    readonly curve: string;
    /** A boolean indicating whther this instance represents a private or public EC key. */
    readonly isPrivateECKey: boolean;
    /** The public x coordinate's big endian representation for the elliptic curve point as a Buffer. */
    readonly x: Buffer;
    /** The public y coordinate's big endian representation for the elliptic curve point as a Buffer. */
    readonly y: Buffer;
    /** The private d coordinate's big endian representation for the elliptic curve point as a Buffer. */
    readonly d: Buffer;
    /** The EC key curve name in RFC-7518 format (e.g. P-256). */
    readonly jsonCurve: string;
    /** The uncompressed and prefixed (0x04) concatenation of the x and y public coordinates' big endian representation, as described in SEC-1 ECC section 2.3.3. */
    readonly publicCodePoint: Buffer;
    /** Return this instance if this key is a public key, or create a new ECKey instance not including the private components of the key. */
    asPublicECKey(): ECKey;
    /** A simple shortcut for createECDH().computeSecret(otherKey) as explained below. */
    computeSecret(otherKey: ECKey): Buffer;
    /** Create a standard Node ECDH object instance whose computeSecret(...) function accepts also ECKey (as in, this class) instances. */
    createECDH(): ECDH;
    /** Create a standard Node Sign object whose sign(...) function is automatically populated with this instance. */
    createSign(hash: string): Sign;
    /** Create a standard Node Verify object whose verify(...) function is automatically populated with this instance. */
    createVerify(hash: string): Verify;
    /** Encode this EC key, optionally using the specified format (defaults to pem). */
    toBuffer(format: string): Buffer;
    /** Encode this EC key, optionally using the specified format (defaults to pem). */
    toString(format: string): string;
    /** Formats this ECKey as a JSON Web Key as specified by RFC-7517. */
    toJSON(): { kty: string; crv: string; x: string; y: string; d: string };
  }
}
