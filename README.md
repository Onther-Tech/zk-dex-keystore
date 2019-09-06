# Usage

```js
const KeyStore = require('.');

const crypto = require('crypto');


// create a new private key
const dk = KeyStore.create();

console.log("dk.privateKey", dk.privateKey.toString('hex'));
console.log("dk.iv", dk.iv.toString('hex'));
console.log("dk.salt", dk.salt.toString('hex'));

const password = 'some-password'

// export to keystore object from private key
const exportedObj = KeyStore.dump(password, dk.privateKey, dk.salt, dk.iv);

console.log("exportedObj", JSON.stringify(exportedObj, null, 2));

// recover private key from keystore object
const recoverredPrivateKey = KeyStore.recover(password, exportedObj);
console.log('recoverredPrivateKey', recoverredPrivateKey.toString('hex'));


// zk-dex abstract classes
const privKey = new KeyStore.ZkDexPrivateKey(dk.privateKey);
console.log("ZkDexPrivateKey", privKey.toHex(), privKey.toBase58(), privKey.toBuffer());

const pubKey = privKey.toPubKey();
console.log("ZkDexPublicKey", pubKey.toHex(), pubKey.toBase58());

const address = pubKey.toAddress();
console.log("ZkDexAddress", address.toString(), address.toBase58());

// zk-dex-private-key to keystore object
const saltBytes = KeyStore.constants.keyBytes + KeyStore.constants.ivBytes;
const ivBytes = KeyStore.constants.ivBytes;

const randomBytes = crypto.randomBytes(saltBytes + ivBytes);

const obj = KeyStore.dump(password, privKey.toHex().slice(2), randomBytes.slice(saltBytes), randomBytes.slice(saltBytes, saltBytes + ivBytes));

console.log("zk-dex-private-key to keystore object", obj);

// keystore object to zk-dex-private-key
const privBuf = KeyStore.recover(password, obj);
const pk = new KeyStore.ZkDexPrivateKey(privBuf);

console.log("zk-dex-private-key from keystore object", pk.toHex(), pk);
```