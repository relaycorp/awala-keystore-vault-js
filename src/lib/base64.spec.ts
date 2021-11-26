import bufferToArray from 'buffer-to-arraybuffer';

import { expectBuffersToEqual } from './_test_utils';
import { base64Decode, base64Encode } from './base64';

const valueDecoded = 'hi';
const valueEncoded = 'aGk=';

describe('base64Encode', () => {
  test('Buffer should be base64 encoded', () => {
    const input = Buffer.from(valueDecoded);

    expect(base64Encode(input)).toEqual(valueEncoded);
  });

  test('ArrayBuffer should be base64 encoded', () => {
    const input = bufferToArray(Buffer.from(valueDecoded));

    expect(base64Encode(input)).toEqual(valueEncoded);
  });
});

test('base64Decode should decode input', () => {
  const expectedOutput = Buffer.from(valueDecoded);

  expectBuffersToEqual(base64Decode(valueEncoded), expectedOutput);
});
