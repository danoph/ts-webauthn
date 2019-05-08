import * as CBOR from 'cbor-js';

export class RandomChallengeGenerator {
  generate() {
    //return Uint8Array.from(randomStringFromServer, c => c.charCodeAt(0)),
    let challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    return challenge;
  }
}

class CredentialIdLengthProvider {
  private _dataView: DataView;

  constructor(private _authData) {
    this._dataView = new DataView(new ArrayBuffer(2));
    const idLenBytes = this._authData.slice(53, 55);
    idLenBytes.forEach((value, index) => this._dataView.setUint8(index, value));
  }

  idLength() {
    return this._dataView.getUint16(0); // typescript complains but this works
  }
}

class CredentialAttestationAuthData {
  private _credentialIdLength: number;

  constructor(private _authData) {
    const idLengthProvider = new CredentialIdLengthProvider(_authData);
    this._credentialIdLength = idLengthProvider.idLength();
  }

  credentialId() {
    return this._authData.slice(55, this._credentialIdLength);
  }

  publicKey() {
    const publicKeyBytes = this._authData.slice(55 + this._credentialIdLength);
    return CBOR.decode(publicKeyBytes.buffer);
  }
}

class CredentialAttestation {
  attestation;
  authData: CredentialAttestationAuthData;

  constructor(private _rawAttestationObject) {
    this.attestation = CBOR.decode(_rawAttestationObject);
    this.authData = new CredentialAttestationAuthData(this.attestation.authData);
  }

  publicKey() {
    return this.authData.publicKey();
  }
}

class CredentialClientDataJson {
  private _decoded;

  constructor(private _clientDataJSON, private _decoder = new TextDecoder()) {
    this._decoded = JSON.parse(this._decoder.decode(_clientDataJSON));
  }

  challenge() {
    return this._decoded.challenge;
  }

  origin() {
    return this._decoded.origin;
  }

  authType() {
    return this._decoded.type;
  }
}

export class CredentialInfo {
  id: Base64UrlEncodedString;
  attestation: CredentialAttestation;
  clientDataJson: CredentialClientDataJson;

  //constructor(private _credential: PublicKeyCredential) {}
  constructor(private _credential) {
    this.id = new Base64UrlEncodedString(_credential.id);
    this.attestation = new CredentialAttestation(_credential.response.attestationObject);
    this.clientDataJson = new CredentialClientDataJson(_credential.response.clientDataJSON);
  }
}

export class Base64StringBuilder {
  static BASE64_URL_ENCODED_REGEX = /(\-|_)+/g;
  //static BASE64_NONURL_ENCODED_REGEX = /(\+|\=|\/)+/g;

  static build(str): Base64EncodedString|Base64UrlEncodedString {
    if (Base64StringBuilder.BASE64_URL_ENCODED_REGEX.test(str)) {
      return new Base64UrlEncodedString(str);
    } else {
      return new Base64EncodedString(str);
    }
  }
}

export class Base64EncodedString {
  //BASE64_NONURL_ENCODED_REGEX = new RegExp('(\+|\=|\/)+', 'g');
  BASE64_URL_ENCODED_REGEX = /(\-|_)+/g;

  constructor(private _str) {
    if (this.BASE64_URL_ENCODED_REGEX.test(_str)) {
      throw "String provided is not base64 encoded.";
    }
  }

  toBase64Url() {
    return this._str.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=+$/, '');
  }

  toBase64() {
    return this._str;
  }

  toArrayBuffer() {
    return base64DecToArr(this.toBase64());
  }
}

export class Base64UrlEncodedString {
  //BASE64_NONURL_ENCODED_REGEX = new RegExp('(\+|\=|\/)+', 'g');
  BASE64_NONURL_ENCODED_REGEX = /(\+|\=|\/)+/g;

  constructor(private _str) {
    //const badString = 'h/FoAgT9GbyRg0d4dYWE28GBeOGlm2UnKWTOCghY6JjpKU7KB4twkqfwDYkC4YX9GsS5Jt+Qj5ulbkTHgiri9g==';
    //const goodString = '23UOCCiZU3MhMEfISeHkh-pfyno1iqakU_9ZEZiZKJVCt0QzmbalJwmSbhLFND8tQ64GjsAnhGAKd76TDo7PCg';

    if (this.BASE64_NONURL_ENCODED_REGEX.test(_str)) {
      throw "String provided is not base64 url encoded.";
    }
  }

  toBase64Url() {
    return this._str;
  }

  toBase64() {
    return (this._str + '===')
      .slice(0, this._str.length + (this._str.length % 4))
      .replace(/-/g, '+').replace(/_/g, '/');
  }

  toArrayBuffer() {
    return base64DecToArr(this.toBase64());
  }
}


/*\
|*|
|*|  Base64 / binary data / UTF-8 strings utilities (#1)
|*|
|*|  https://developer.mozilla.org/en-US/docs/Web/API/WindowBase64/Base64_encoding_and_decoding
|*|
|*|  Author: madmurphy
|*|
\*/

/* Array of bytes to base64 string decoding */

const b64ToUint6 = (nChr) => {
  return nChr > 64 && nChr < 91 ?
      nChr - 65
    : nChr > 96 && nChr < 123 ?
      nChr - 71
    : nChr > 47 && nChr < 58 ?
      nChr + 4
    : nChr === 43 ?
      62
    : nChr === 47 ?
      63
    :
      0;
}

const base64DecToArr = (sBase64, nBlockSize = null) => {
  var
    sB64Enc = sBase64.replace(/[^A-Za-z0-9\+\/]/g, ""), nInLen = sB64Enc.length,
    nOutLen = nBlockSize ? Math.ceil((nInLen * 3 + 1 >>> 2) / nBlockSize) * nBlockSize : nInLen * 3 + 1 >>> 2, aBytes = new Uint8Array(nOutLen);

  for (var nMod3, nMod4, nUint24 = 0, nOutIdx = 0, nInIdx = 0; nInIdx < nInLen; nInIdx++) {
    nMod4 = nInIdx & 3;
    nUint24 |= b64ToUint6(sB64Enc.charCodeAt(nInIdx)) << 18 - 6 * nMod4;
    if (nMod4 === 3 || nInLen - nInIdx === 1) {
      for (nMod3 = 0; nMod3 < 3 && nOutIdx < nOutLen; nMod3++, nOutIdx++) {
        aBytes[nOutIdx] = nUint24 >>> (16 >>> nMod3 & 24) & 255;
      }
      nUint24 = 0;
    }
  }

  return aBytes;
}

/* Base64 string to array encoding */

const uint6ToB64 = (nUint6) => {
  return nUint6 < 26 ?
      nUint6 + 65
    : nUint6 < 52 ?
      nUint6 + 71
    : nUint6 < 62 ?
      nUint6 - 4
    : nUint6 === 62 ?
      43
    : nUint6 === 63 ?
      47
    :
      65;
}

const base64EncArr = (aBytes) => {
  var eqLen = (3 - (aBytes.length % 3)) % 3, sB64Enc = "";

  for (var nMod3, nLen = aBytes.length, nUint24 = 0, nIdx = 0; nIdx < nLen; nIdx++) {
    nMod3 = nIdx % 3;
    /* Uncomment the following line in order to split the output in lines 76-character long: */
    /*
    if (nIdx > 0 && (nIdx * 4 / 3) % 76 === 0) { sB64Enc += "\r\n"; }
    */
    nUint24 |= aBytes[nIdx] << (16 >>> nMod3 & 24);
    if (nMod3 === 2 || aBytes.length - nIdx === 1) {
      sB64Enc += String.fromCharCode(uint6ToB64(nUint24 >>> 18 & 63), uint6ToB64(nUint24 >>> 12 & 63), uint6ToB64(nUint24 >>> 6 & 63), uint6ToB64(nUint24 & 63));
      nUint24 = 0;
    }
  }

  return  eqLen === 0 ?
      sB64Enc
    :
      sB64Enc.substring(0, sB64Enc.length - eqLen) + (eqLen === 1 ? "=" : "==");

}
