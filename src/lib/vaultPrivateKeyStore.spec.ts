import {
  derSerializePrivateKey,
  generateECDHKeyPair,
  generateRSAKeyPair,
  getPrivateAddressFromIdentityKey,
  PrivateKeyStoreError,
  UnknownKeyError,
} from '@relaycorp/relaynet-core';
import axios, { AxiosRequestConfig } from 'axios';
import * as http from 'http';
import * as https from 'https';

import { expectBuffersToEqual, expectPromiseToReject, getPromiseRejection } from './_test_utils';
import { base64Encode } from './utils';
import { VaultPrivateKeyStore } from './vaultPrivateKeyStore';

describe('VaultPrivateKeyStore', () => {
  const mockAxiosCreate = jest.spyOn(axios, 'create');
  beforeEach(() => {
    mockAxiosCreate.mockReset();
  });
  afterAll(() => {
    mockAxiosCreate.mockRestore();
  });

  const stubVaultUrl = 'http://localhost:8200';
  const stubKvPath = 'pohttp-private-keys';
  const stubVaultToken = 'letmein';

  const TOMORROW = new Date();
  TOMORROW.setDate(TOMORROW.getDate() + 1);

  const sessionKeyId = Buffer.from([9, 7, 5, 3, 1]);
  let sessionKeyPair: CryptoKeyPair;
  let identityPrivateKey: CryptoKey;
  let privateAddress: string;
  let recipientKeyPair: CryptoKeyPair;
  let recipientPrivateAddress: string;
  beforeAll(async () => {
    sessionKeyPair = await generateECDHKeyPair();

    const senderKeyPair = await generateRSAKeyPair();
    identityPrivateKey = senderKeyPair.privateKey;
    privateAddress = await getPrivateAddressFromIdentityKey(senderKeyPair.publicKey);

    recipientKeyPair = await generateRSAKeyPair();
    recipientPrivateAddress = await getPrivateAddressFromIdentityKey(recipientKeyPair.publicKey);
  });

  describe('constructor', () => {
    describe('Axios client', () => {
      const mockResponseInterceptorUse = jest.fn();
      beforeEach(() => {
        mockAxiosCreate.mockReturnValue({
          interceptors: {
            // @ts-ignore
            response: {
              use: mockResponseInterceptorUse,
            },
          },
        });
      });

      let axiosCreateCallOptions: AxiosRequestConfig;
      beforeEach(() => {
        // tslint:disable-next-line:no-unused-expression
        new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

        expect(mockAxiosCreate).toBeCalledTimes(1);
        axiosCreateCallOptions = mockAxiosCreate.mock.calls[0][0] as AxiosRequestConfig;
      });

      test('Keep alive should be used', () => {
        expect(axiosCreateCallOptions.httpsAgent).toBeInstanceOf(https.Agent);
        expect(axiosCreateCallOptions.httpsAgent).toHaveProperty('keepAlive', true);

        expect(axiosCreateCallOptions.httpAgent).toBeInstanceOf(http.Agent);
        expect(axiosCreateCallOptions.httpAgent).toHaveProperty('keepAlive', true);
      });

      test('A timeout of 3 seconds should be used', () => {
        expect(axiosCreateCallOptions).toHaveProperty('timeout', 3000);
      });

      test('Base URL should include Vault URL and KV path', () => {
        expect(axiosCreateCallOptions).toHaveProperty(
          'baseURL',
          `${stubVaultUrl}/v1/${stubKvPath}/data`,
        );
      });

      test('Base URL should be normalized', () => {
        mockAxiosCreate.mockClear();

        // tslint:disable-next-line:no-unused-expression
        new VaultPrivateKeyStore(`${stubVaultUrl}/`, stubVaultToken, `/${stubKvPath}/`);

        expect(mockAxiosCreate.mock.calls[0][0]).toHaveProperty(
          'baseURL',
          `${stubVaultUrl}/v1/${stubKvPath}/data`,
        );
      });

      test('Vault token should be included in the headers', () => {
        expect(axiosCreateCallOptions).toHaveProperty('headers.X-Vault-Token', stubVaultToken);
      });

      test('Status validation should be disabled', async () => {
        expect(axiosCreateCallOptions).toHaveProperty('validateStatus', null);
      });

      test('An error interceptor that removes sensitive data should be registered', async () => {
        const stubError = { message: 'Denied', sensitive: 's3cr3t' };

        expect(mockResponseInterceptorUse).toBeCalledTimes(1);

        const responseInterceptorCallArgs = mockResponseInterceptorUse.mock.calls[0];
        const errorInterceptor = responseInterceptorCallArgs[1];
        try {
          await errorInterceptor(stubError);
          fail('Expected interceptor to reject');
        } catch (error) {
          expect(error).toHaveProperty('message', stubError.message);
          expect(error).not.toHaveProperty('sensitive');
        }
      });
    });
  });

  describe('Saving', () => {
    const mockAxiosClient = { post: jest.fn(), interceptors: { response: { use: jest.fn() } } };
    beforeEach(() => {
      mockAxiosClient.post.mockReset();
      mockAxiosClient.post.mockResolvedValue({ status: 204 });

      mockAxiosCreate.mockReturnValueOnce(mockAxiosClient as any);
    });

    test('Identity key should be stored', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);
      await store.saveIdentityKey(identityPrivateKey);

      expect(mockAxiosClient.post).toBeCalledTimes(1);
      const postCallArgs = mockAxiosClient.post.mock.calls[0];
      expect(postCallArgs[0]).toEqual(`/i-${privateAddress}`);
      expect(postCallArgs[1]).toHaveProperty(
        'data.privateKey',
        base64Encode(await derSerializePrivateKey(identityPrivateKey)),
      );
    });

    test('Unbound session key should be stored', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);
      await store.saveUnboundSessionKey(sessionKeyPair.privateKey, sessionKeyId);

      expect(mockAxiosClient.post).toBeCalledTimes(1);
      const postCallArgs = mockAxiosClient.post.mock.calls[0];
      expect(postCallArgs[0]).toEqual(`/s-${sessionKeyId.toString('hex')}`);
      expect(postCallArgs[1]).toHaveProperty(
        'data.privateKey',
        base64Encode(await derSerializePrivateKey(sessionKeyPair.privateKey)),
      );
      expect(postCallArgs[1]).toHaveProperty('data.peerPrivateAddress', undefined);
    });

    test('Bound session key should be stored', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);
      await store.saveBoundSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyId,
        recipientPrivateAddress,
      );

      expect(mockAxiosClient.post).toBeCalledTimes(1);
      const postCallArgs = mockAxiosClient.post.mock.calls[0];
      expect(postCallArgs[0]).toEqual(`/s-${sessionKeyId.toString('hex')}`);
      expect(postCallArgs[1]).toHaveProperty(
        'data.privateKey',
        base64Encode(await derSerializePrivateKey(sessionKeyPair.privateKey)),
      );
      expect(postCallArgs[1]).toHaveProperty('data.peerPrivateAddress', recipientPrivateAddress);
    });

    test('Axios errors should be wrapped', async () => {
      const axiosError = new Error('Denied');
      mockAxiosClient.post.mockRejectedValue(axiosError);
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      const error = await getPromiseRejection(
        store.saveIdentityKey(identityPrivateKey),
        PrivateKeyStoreError,
      );

      expect(error.cause()).toEqual(axiosError);
    });

    test('A 200 OK response should be treated as success', async () => {
      mockAxiosClient.post.mockResolvedValue({ status: 200 });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await store.saveIdentityKey(identityPrivateKey);
    });

    test('A 204 No Content response should be treated as success', async () => {
      mockAxiosClient.post.mockResolvedValue({ status: 204 });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await store.saveIdentityKey(identityPrivateKey);
    });

    test('A non-200/204 response should raise an error', async () => {
      mockAxiosClient.post.mockResolvedValue({ status: 400, data: {} });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      const error = await getPromiseRejection(
        store.saveIdentityKey(identityPrivateKey),
        PrivateKeyStoreError,
      );

      expect(error.cause()?.message).toEqual('Vault returned a 400 response');
    });

    test('Error messages in 40X/50X responses should be included in error', async () => {
      const errorMessages: ReadonlyArray<any> = ['foo', 'bar'];
      mockAxiosClient.post.mockResolvedValue({ status: 400, data: { errors: errorMessages } });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      const error = await getPromiseRejection(
        store.saveIdentityKey(identityPrivateKey),
        PrivateKeyStoreError,
      );

      expect(error.cause()?.message).toEqual(
        `Vault returned a 400 response (${errorMessages.join(', ')})`,
      );
    });
  });

  describe('Retrieval', () => {
    const mockAxiosClient = { get: jest.fn(), interceptors: { response: { use: jest.fn() } } };

    beforeEach(async () => {
      mockAxiosClient.get.mockReset();
      mockAxiosClient.get.mockResolvedValue(
        makeVaultGETResponse(
          {
            peerPrivateAddress: recipientPrivateAddress,
            privateKey: base64Encode(await derSerializePrivateKey(sessionKeyPair.privateKey)),
            type: 'session-subsequent',
          },
          200,
        ),
      );

      mockAxiosCreate.mockReturnValueOnce(mockAxiosClient as any);
    });

    test('Endpoint path should be the key id', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await store.fetchSessionKey(sessionKeyId, recipientPrivateAddress);

      expect(mockAxiosClient.get).toBeCalledTimes(1);
      const getCallArgs = mockAxiosClient.get.mock.calls[0];
      expect(getCallArgs[0]).toEqual(`/${sessionKeyId.toString('hex')}`);
    });

    test('Private key should be returned', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      const privateKey = await store.fetchSessionKey(sessionKeyId, recipientPrivateAddress);

      expectBuffersToEqual(
        await derSerializePrivateKey(privateKey),
        await derSerializePrivateKey(sessionKeyPair.privateKey),
      );
    });

    test('Key type should be returned', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      // We can tell the type was returned because it was checked
      await expect(store.retrieveIdentityKey(privateAddress)).rejects.toMatchObject({
        message: expect.stringMatching(/is not a node key/),
      });
    });

    test('Session key should not be returned if bound to another recipient', async () => {
      const peerPrivateAddress = await getPrivateAddressFromIdentityKey(recipientKeyPair.publicKey);
      mockAxiosClient.get.mockResolvedValue(
        makeVaultGETResponse(
          {
            peerPrivateAddress,
            privateKey: base64Encode(await derSerializePrivateKey(sessionKeyPair.privateKey)),
            type: 'session-subsequent',
          },
          200,
        ),
      );
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      const differentRecipientKeyPair = await generateRSAKeyPair();
      const differentPeerPrivateAddress = await getPrivateAddressFromIdentityKey(
        differentRecipientKeyPair.publicKey,
      );
      // We can tell the digest was returned because it was checked:
      await expect(
        store.fetchSessionKey(sessionKeyId, differentPeerPrivateAddress),
      ).rejects.toEqual(
        new UnknownKeyError(
          `Session key ${sessionKeyId.toString('hex')} is bound to another recipient ` +
            `(${peerPrivateAddress}, not ${differentPeerPrivateAddress})`,
        ),
      );
    });

    test('Axios errors should be wrapped', async () => {
      mockAxiosClient.get.mockRejectedValue(new Error('Denied'));
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expectPromiseToReject(
        store.fetchSessionKey(sessionKeyId, recipientPrivateAddress),
        new PrivateKeyStoreError(`Failed to retrieve key: Denied`),
      );
    });

    test('A 404 response should raise an UnknownKeyError', async () => {
      mockAxiosClient.get.mockResolvedValue({ status: 404 });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expect(
        store.fetchSessionKey(sessionKeyId, recipientPrivateAddress),
      ).rejects.toBeInstanceOf(UnknownKeyError);
    });

    test('Any status other than 200 or 404 should raise a PrivateKeyStoreError', async () => {
      mockAxiosClient.get.mockResolvedValue({ status: 204, data: {} });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expectPromiseToReject(
        store.fetchSessionKey(sessionKeyId, recipientPrivateAddress),
        new PrivateKeyStoreError(`Failed to retrieve key: Vault returned a 204 response`),
      );
    });

    test('Error messages in 40X/50X responses should be included in error', async () => {
      const errorMessages: ReadonlyArray<any> = ['foo', 'bar'];
      mockAxiosClient.get.mockResolvedValue({ status: 204, data: { errors: errorMessages } });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expectPromiseToReject(
        store.fetchSessionKey(sessionKeyId, recipientPrivateAddress),
        new PrivateKeyStoreError(
          `Failed to retrieve key: Vault returned a 204 response (${errorMessages.join(', ')})`,
        ),
      );
    });

    function makeVaultGETResponse(data: any, status: number): any {
      return {
        data: { data: { data } },
        status,
      };
    }
  });
});
