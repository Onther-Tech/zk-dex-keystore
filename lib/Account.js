const { Point } = require('babyjubjub/lib/Point');
const { PublicKey, PrivateKey } = require('babyjubjub');
const { padLeft } = require('web3-utils');

const {
  encodeBase58,
  decodeBase58,
  getSkHex,
  marshal,
  unmarshal,
  addZkPrefix,
  removeZkPrefix,
} = require('./utils');

const PRIVATE_KEY_HEX_LENGTH = 32;

const PUBLIC_KEY_X_HEX_LENGTH = 64;
const PUBLIC_KEY_Y_HEX_LENGTH = 64;

const ADDRESS_HEX_LENGTH = PUBLIC_KEY_X_HEX_LENGTH + PUBLIC_KEY_Y_HEX_LENGTH;

// TODO: we should represent address only using 254 bits for x-coordinate and 1 bit for y-coordinate of public key.
const ADDRESS_BASE58_MIN_LENGTH = 86; // without zk prefix
const ADDRESS_BASE58_MAX_LENGTH = 88; // without zk prefix


/**
 * @TODO Use buffer instead of string
 * @notice ZkDexPrivateKey holds secret key (private key) of note owner
 */
class ZkDexPrivateKey {
  /**
   * @param {String} privKey hex string
   */
  constructor(privKey) {
    this.privKey = new PrivateKey(marshal(privKey));
  }

  static randomPrivateKey() {
    return new ZkDexPrivateKey(getSkHex());
  }

  /**
   * @returns {ZkDexPublicKey}
   */
  toPubKey() {
    this.pubKey = this.pubKey || PublicKey.fromPrivate(this.privKey);

    return new ZkDexPublicKey(
      this.pubKey.p.x.n.toString(16),
      this.pubKey.p.y.n.toString(16),
    );
  }

  /**
   * @returns {ZkDexAddress}
   */
  toAddress() {
    return this.toPubKey().toAddress();
  }

  /**
   * @returns {String} hex-encoded string of private key.
   */
  toHex() {
    return padLeft(marshal(this.privKey.s.n.toString(16)), PRIVATE_KEY_HEX_LENGTH);
  }

  /**
   * @returns {String} base58-encoded string of private key.
   */
  toBase58() {
    return encodeBase58(this.toHex());
  }

  toBuffer() {
    return Buffer.from(unmarshal(this.toHex()), 'hex')
  }
}

/**
 * @notice ZkDexPublicKey is public key of ZkDexPrivateKey.
 */
class ZkDexPublicKey {
  /**
   * @param {String} x hex string of x-coordinate of public key
   * @param {String} y hex string of y-coordinate of public key
   */
  constructor(x, y) {
    this.pubKey = new Point(marshal(x), marshal(y));
  }

  toAddress() {
    return new ZkDexAddress(this.toHex());
  }

  xToHex() {
    return padLeft(marshal(this.pubKey.x.n.toString(16)), PUBLIC_KEY_X_HEX_LENGTH);
  }

  yToHex() {
    return padLeft(marshal(this.pubKey.y.n.toString(16)), PUBLIC_KEY_Y_HEX_LENGTH);
  }

  toHex() {
    return marshal(unmarshal(this.xToHex()) + unmarshal(this.yToHex()))
  }

  xToBase58() {
    return encodeBase58(this.xToHex());
  }

  yToBase58() {
    return encodeBase58(this.yToHex());
  }

  toBase58() {
    return encodeBase58(this.toHex());
  }
}

/**
 * @TODO we should represent address only using 254 bits for x-coordinate and 1 bit for y-coordinate of public key.
 * @notice ZkDexAddress represents ZkDexPublicKey as base58-encoded string with 'zk' prefix.
 */
class ZkDexAddress {
  /**
   * To get ZkDexAddress from base58-encoded string, use ZkDexAddress.fromBase58
   * @param {String} address hex-encoded string
   */
  constructor(address) {
    this.address = padLeft(marshal(address), ADDRESS_HEX_LENGTH);
  }

  static fromHex(str) {
    return new ZkDexAddress(str);
  }

  static fromBase58(str) {
    return new ZkDexAddress(decodeBase58(str));
  }

  /**
   * @notice Only use for zk-address with 'zk' prefix
   * @param {String} str zk-dex address with prefix 'zk'
   */
  static fromString(str) {
    return new ZkDexAddress(decodeBase58(removeZkPrefix(str)));
  }


  toPubKey() {
    const address = unmarshal(padLeft(this.address, ADDRESS_HEX_LENGTH));
    const x = address.slice(0, PUBLIC_KEY_X_HEX_LENGTH);
    const y = address.slice(PUBLIC_KEY_X_HEX_LENGTH, PUBLIC_KEY_X_HEX_LENGTH + PUBLIC_KEY_Y_HEX_LENGTH);
    return new ZkDexPublicKey(x, y);
  }

  toHex() {
    return padLeft(marshal(this.address), ADDRESS_HEX_LENGTH);
  }

  toBase58() {
    return encodeBase58(this.toHex());
  }

  toString() {
    return addZkPrefix(encodeBase58(this.toHex()));
  }
}

module.exports = {
  ZkDexPrivateKey,
  ZkDexPublicKey,
  ZkDexAddress,
};