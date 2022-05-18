/* tslint:disable:max-classes-per-file */

import {
  derDeserializeRSAPrivateKey,
  derSerializePrivateKey,
  PrivateKeyStore,
  SessionPrivateKeyData,
} from '@relaycorp/relaynet-core';
import axios, { AxiosInstance } from 'axios';
import { Agent as HttpAgent } from 'http';
import { Agent as HttpsAgent } from 'https';

import { base64Decode, base64Encode } from './base64';
import { VaultStoreError } from './VaultStoreError';

interface BaseKeyDataEncoded {
  readonly privateKey: string;
}

interface IdentityKeyDataEncoded extends BaseKeyDataEncoded {}

interface SessionKeyDataEncoded extends BaseKeyDataEncoded {
  readonly privateAddress: string;
  readonly peerPrivateAddress?: string;
}

type KeyDataEncoded = IdentityKeyDataEncoded | SessionKeyDataEncoded;

interface BaseKeyDataDecoded {
  readonly privateKey: Buffer;
}

interface IdentityKeyDataDecoded extends BaseKeyDataDecoded {}

interface SessionKeyDataDecoded extends BaseKeyDataDecoded {
  readonly peerPrivateAddress: string;
  readonly privateAddress: string;
}

type KeyDataDecoded = IdentityKeyDataDecoded | SessionKeyDataDecoded;

export class VaultPrivateKeyStore extends PrivateKeyStore {
  protected readonly axiosClient: AxiosInstance;

  constructor(vaultUrl: string, vaultToken: string, kvPath: string) {
    super();

    const baseURL = buildBaseVaultUrl(vaultUrl, kvPath);
    this.axiosClient = axios.create({
      baseURL,
      headers: { 'X-Vault-Token': vaultToken },
      httpAgent: new HttpAgent({ keepAlive: true }),
      httpsAgent: new HttpsAgent({ keepAlive: true }),
      timeout: 3000,
      validateStatus: null as any,
    });

    // Sanitize errors to avoid leaking sensitive data, which apparently is a feature:
    // https://github.com/axios/axios/issues/2602
    this.axiosClient.interceptors.response.use(undefined, async (error) =>
      Promise.reject(new Error(error.message)),
    );
  }

  protected async saveIdentityKey(privateAddress: string, privateKey: CryptoKey): Promise<void> {
    const keySerialized = await derSerializePrivateKey(privateKey);
    await this.saveData(keySerialized, `i-${privateAddress}`);
  }

  protected async saveSessionKeySerialized(
    keyId: string,
    keySerialized: Buffer,
    privateAddress: string,
    peerPrivateAddress?: string,
  ): Promise<void> {
    await this.saveData(keySerialized, `s-${keyId}`, {
      peerPrivateAddress,
      privateAddress,
    });
  }

  public async retrieveIdentityKey(privateAddress: string): Promise<CryptoKey | null> {
    const keyData = await this.retrieveData(`i-${privateAddress}`);
    if (!keyData?.privateKey) {
      return null;
    }
    return derDeserializeRSAPrivateKey(keyData.privateKey);
  }

  private async saveData(
    keySerialized: Buffer,
    keyId: string,
    keyData: Omit<KeyDataEncoded, 'privateKey'> = {},
  ): Promise<void> {
    const keyBase64 = base64Encode(keySerialized);
    const data: KeyDataEncoded = { privateKey: keyBase64, ...keyData };
    const response = await this.axiosClient.post(`/${keyId}`, { data });
    if (response.status !== 200 && response.status !== 204) {
      throw new VaultStoreError(
        `Vault returned a ${response.status} response`,
        response.data.errors,
      );
    }
  }

  protected async retrieveSessionKeyData(keyId: string): Promise<SessionPrivateKeyData | null> {
    const keyData = await this.retrieveData(`s-${keyId}`);
    if (!keyData) {
      return null;
    }
    return {
      keySerialized: keyData.privateKey,
      peerPrivateAddress: (keyData as SessionKeyDataDecoded).peerPrivateAddress,
      privateAddress: (keyData as SessionKeyDataDecoded).privateAddress,
    };
  }

  private async retrieveData(keyId: string): Promise<KeyDataDecoded | null> {
    const response = await this.axiosClient.get(`/${keyId}`);

    if (response.status === 404) {
      return null;
    }
    if (response.status !== 200) {
      throw new VaultStoreError(
        `Vault returned a ${response.status} response`,
        response.data.errors,
      );
    }

    const vaultData = response.data.data.data as KeyDataEncoded;
    return {
      peerPrivateAddress: (vaultData as SessionKeyDataEncoded).peerPrivateAddress,
      privateAddress: (vaultData as SessionKeyDataEncoded).privateAddress,
      privateKey: base64Decode(vaultData.privateKey),
    };
  }
}

function buildBaseVaultUrl(vaultUrl: string, kvPath: string): string {
  const sanitizedVaultUrl = vaultUrl.replace(/\/+$/, '');
  const sanitizedKvPath = kvPath.replace(/^\/+/, '').replace(/\/+/, '');
  return `${sanitizedVaultUrl}/v1/${sanitizedKvPath}/data`;
}
