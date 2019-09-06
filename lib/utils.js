const bs58 = require('bs58');
const { PublicKey, PrivateKey } = require('babyjubjub');
const crypto = require('crypto');
const Web3Utils = require('web3-utils');


function marshal(str) {
  if (!str) throw new Error("Cannot add hex prefix empty string");

  return '0x' + unmarshal(str);
}

function unmarshal(_str) {
  let str;
  if (_str instanceof Buffer) {
    str = _str.toString('hex');
  } else {
    str = _str.trim();
  }

  if (!str) throw new Error("Cannot remove hex prefix empty string");

  const i = str.lastIndexOf("0x");
  if (i >= 0) str = str.slice(i+2);

  if (str.length % 2 === 1) {
    str = '0' + str;
  }

  return str;
}

const ADDRESS_PREFIX = 'zk';

/**
 * @function addZkPrefix add 'zk' prefix to base58-encoded string
 * @param {String} str
 * @returns {String}
 */
function addZkPrefix(str) {
  if (str.startsWith(ADDRESS_PREFIX)) return str;
  return ADDRESS_PREFIX + str;
}

/**
 * @function removeZkPrefix remove 'zk' prefix from base58-encoded string
 * @param {String} str
 * @returns {String}
 */
function removeZkPrefix(str) {
  if (str.startsWith(ADDRESS_PREFIX)) return str.slice(2);
  return str;
}


function getSk() {
  let sk = PrivateKey.getRandObj().field;
  return sk;
}

function getSkHex() {
  return PrivateKey.getRandObj().hexString;
}

function getPrivKey(sk) {
  return new PrivateKey(sk);
}

function getPubKey(privKey) {
  return PublicKey.fromPrivate(privKey);
}

function getOwner(sk) {
  const privKey = getPrivKey(sk);
  const pubKey = getPubKey(privKey);
  const pubKeyX = pubKey.p.x.n.toString(16, 64);
  const pubKeyY = pubKey.p.y.n.toString(16, 64);

  return [pubKeyX, pubKeyY]
}

/**
 * @param {String} hexString hex-encoded string
 * @returns {String} base58-encoded string
 */
function encodeBase58(hexString) {
  return bs58.encode(Buffer.from(unmarshal(hexString), 'hex'));
}

/**
 *
 * @param {String} base58String base58-encoded string
 * @returns {String} hex-encoded string
 */
function decodeBase58(base58String) {
  return bs58.decode(base58String).toString('hex');
}

module.exports = {
  getSk,
  getSkHex,
  getPrivKey,
  getPubKey,
  getOwner,
  encodeBase58,
  decodeBase58,
  marshal,
  unmarshal,
  addZkPrefix,
  removeZkPrefix,
}