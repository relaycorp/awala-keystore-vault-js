/* tslint:disable:max-classes-per-file */

import { PrivateKeyStore, SessionPrivateKeyData } from '@relaycorp/relaynet-core';
import axios, { AxiosInstance } from 'axios';
import { Agent as HttpAgent } from 'http';
import { Agent as HttpsAgent } from 'https';

import { base64Decode, base64Encode } from './base64';

class VaultStoreError extends Error {
  constructor(message: string, responseErrorMessages?: readonly string[]) {
    const finalErrorMessage = responseErrorMessages
      ? `${message} (${responseErrorMessages.join(', ')})`
      : message;
    super(finalErrorMessage);
  }
}

interface KeyDataEncoded {
  readonly privateKey: string;
  readonly peerPrivateAddress?: string;
}

interface KeyDataDecoded {
  readonly privateKey: Buffer;
  readonly peerPrivateAddress?: string;
}

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

  protected async saveIdentityKeySerialized(
    privateAddress: string,
    keySerialized: Buffer,
  ): Promise<void> {
    await this.saveData(keySerialized, `i-${privateAddress}`);
  }

  protected async saveSessionKeySerialized(
    keyId: string,
    keySerialized: Buffer,
    peerPrivateAddress?: string,
  ): Promise<void> {
    await this.saveData(keySerialized, `s-${keyId}`, peerPrivateAddress);
  }

  protected async retrieveIdentityKeySerialized(privateAddress: string): Promise<Buffer | null> {
    const keyData = await this.retrieveData(`i-${privateAddress}`);
    return keyData?.privateKey ?? null;
  }

  protected async retrieveSessionKeyData(keyId: string): Promise<SessionPrivateKeyData | null> {
    const keyData = await this.retrieveData(`s-${keyId}`);
    if (!keyData) {
      return null;
    }
    return {
      keySerialized: keyData.privateKey,
      peerPrivateAddress: keyData.peerPrivateAddress,
    };
  }

  private async saveData(
    keySerialized: Buffer,
    keyId: string,
    peerPrivateAddress?: string,
  ): Promise<void> {
    const keyBase64 = base64Encode(keySerialized);
    const data: KeyDataEncoded = {
      peerPrivateAddress,
      privateKey: keyBase64,
    };
    const response = await this.axiosClient.post(`/${keyId}`, { data });
    if (response.status !== 200 && response.status !== 204) {
      throw new VaultStoreError(
        `Vault returned a ${response.status} response`,
        response.data.errors,
      );
    }
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
      peerPrivateAddress: vaultData.peerPrivateAddress,
      privateKey: base64Decode(vaultData.privateKey),
    };
  }
}

function buildBaseVaultUrl(vaultUrl: string, kvPath: string): string {
  const sanitizedVaultUrl = vaultUrl.replace(/\/+$/, '');
  const sanitizedKvPath = kvPath.replace(/^\/+/, '').replace(/\/+/, '');
  return `${sanitizedVaultUrl}/v1/${sanitizedKvPath}/data`;
}
