export function expectBuffersToEqual(
  buffer1: Buffer | ArrayBuffer,
  buffer2: Buffer | ArrayBuffer,
): void {
  if (buffer1 instanceof Buffer) {
    expect(buffer2).toBeInstanceOf(Buffer);
    expect(buffer1.equals(buffer2 as Buffer)).toBeTrue();
  } else {
    expect(buffer1).toBeInstanceOf(ArrayBuffer);
    expect(buffer2).toBeInstanceOf(ArrayBuffer);

    const actualBuffer1 = Buffer.from(buffer1);
    const actualBuffer2 = Buffer.from(buffer2);
    expect(actualBuffer1.equals(actualBuffer2)).toBeTrue();
  }
}

export async function getPromiseRejection<E extends Error>(
  promise: Promise<any>,
  expectedErrorClass: new (...args: readonly any[]) => E,
): Promise<E> {
  try {
    await promise;
  } catch (error) {
    if (!(error instanceof expectedErrorClass)) {
      throw new Error(`"${error}" does not extend ${expectedErrorClass.name}`);
    }
    return error;
  }
  throw new Error('Expected project to reject');
}

export async function expectPromiseToReject(
  promise: Promise<any>,
  expectedError: Error,
): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toHaveProperty('message', expectedError.message);
    expect(error).toBeInstanceOf(expectedError.constructor);
    return;
  }
  throw new Error(`Expected promise to throw error ${expectedError}`);
}
