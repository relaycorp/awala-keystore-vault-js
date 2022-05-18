export class VaultStoreError extends Error {
  constructor(message: string, responseErrorMessages?: readonly string[]) {
    const finalErrorMessage = responseErrorMessages
      ? `${message} (${responseErrorMessages.join(', ')})`
      : message;
    super(finalErrorMessage);
  }
}
