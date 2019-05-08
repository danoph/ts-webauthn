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
    return Uint8Array.from(window.atob(this.toBase64()), c => c.charCodeAt(0));
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
    return Uint8Array.from(window.atob(this.toBase64()), c => c.charCodeAt(0));
  }
}
