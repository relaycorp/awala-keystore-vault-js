# keystore-vault-js

**Superseded by https://github.com/relaycorp/awala-keystore-cloud-js**

[Vault](https://www.vaultproject.io)-based Private Key Store extension for server-side, Node.js-based applications implementing Relaynet -- For example, public endpoints.

## Install

This library is available on NPM and the latest version can be installed as follows:

```shell
npm i @relaycorp/keystore-vault
```

## Usage

### Initialisation

Once you've configured Vault, you need to initialise `VaultPrivateKeyStore` with the following arguments:

- `vaultUrl`: The URL to Vault. For example, `https://vault.local:8200`.
- `vaultToken`: The auth token.
- `kvPath`: The path to the KV Secrets Engine. Only Version 2 of the engine is supported.

### Adding an identity key

To add an identity key for your own node, use `VaultPrivateKeyStore.saveNodeKey();`. For example:

```typescript
await keyStore.saveNodeKey(identityKeyPair.privateKey, identityCertificate);
```

**Make sure to store the output of `identityCertificate.getSerialNumber()`** because you'll need that identifier to retrieve the private key later.

### Adding an initial session key

To add an initial session key for your own node, use `VaultPrivateKeyStore.saveInitialSessionKey();`. For example:

```typescript
await keyStore.saveInitialSessionKey(sessionKeyPair.privateKey, sessionKeyId);
```

### Signing a RAMF message

To sign a RAMF message, such as a parcel, retrieve the identity key and pass it to the `RAMFMessage.serialize()` method. For example:

```typescript
const privateKey = await keyStore.fetchNodeKey(IDENTITY_KEY_ID);
const parcelSerialized = await parcel.serialize(privateKey);
```

### Decrypting a RAMF message payload

To decrypt the payload of a RAMF message -- for example, to extract the service message from a parcel -- you should simply pass the key store instance to `RAMFMessage.unwrapPayload()`. For example:

```typescript
const serviceMessage = await parcel.unwrapPayload(keyStore);
```

## API documentation

The API documentation can be found on [docs.relaycorp.tech](https://docs.relaycorp.tech/keystore-vault-js/).
