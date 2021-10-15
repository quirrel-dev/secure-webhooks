const FIVE_MINUTES = 5 * 60 * 1000;

// Borrowed and modified from https://github.com/lukeed/worktop/commit/200999a5fccea4cfd559a14d1aff6e191715f354
function timingSafeEqual(one: string, two: string): boolean {
  let different = false;

  const a = stringToUint8Array(one);
  const b = stringToUint8Array(two);

  if (a.byteLength !== b.byteLength) different = true;
  let len = a.length;
  while (len-- > 0) {
    // must check all items until complete
    if (a[len] !== b[len]) different = true;
  }
  return !different;
}

// Borrowed from https://stackoverflow.com/a/40031979
function arrayBufferToHex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)].map(x => x.toString(16).padStart(2, '0')).join('');
}

// Borrowed from https://stackoverflow.com/a/67082926
function arrayBufferToString(buffer: ArrayBuffer) {
  return String.fromCharCode.apply(null, Array.from(new Uint8Array(buffer)));
}

// Borrowed and modified from https://stackoverflow.com/a/67082926
function stringToArrayBuffer(str: string): ArrayBuffer {
  const buffer = new ArrayBuffer(str.length);
  stringToUint8Array(str, buffer);
  return buffer;
}

function stringToUint8Array(str: string, buffer = new ArrayBuffer(str.length)): Uint8Array {
  const bufferInterface = new Uint8Array(buffer);
  Array.from(str).forEach((char, index: number) => bufferInterface[index] = char.charCodeAt(0));
  return bufferInterface;
}

function makeSecureWebhooks(
  getSigner: (secretOrPrivateKey: string) => (input: string) => Promise<string>,
  getVerifier: (
    secretOrPublicKey: string
  ) => (input: string, digest: string) => Promise<boolean>
) {
  return {
    async sign(
      input: string,
      secretOrPrivateKey: string,
      timestamp: number = Date.now()
    ): Promise<string> {
      const signer = getSigner(secretOrPrivateKey);

      return `v=${timestamp},d=${await signer(input + timestamp)}`;
    },
    async verify(
      input: string,
      secret: string,
      signature: string,
      opts: { timeout?: number; timestamp?: number } = {}
    ): Promise<boolean> {
      const match = /v=(\d+),d=(.*)/.exec(signature);
      if (!match) {
        return false;
      }

      const poststamp = Number(match[1]);
      const postDigest = match[2];

      const timestamp = opts?.timestamp ?? Date.now();
      const timeout = opts?.timeout ?? FIVE_MINUTES;

      const difference = Math.abs(timestamp - poststamp);
      if (difference > timeout) {
        return false;
      }

      const verifier = getVerifier(secret);

      return verifier(input + poststamp, postDigest);
    },
  };
}

export type SecureWebhooks = ReturnType<typeof makeSecureWebhooks>;

export const symmetric = makeSecureWebhooks(
  secret => async input => {
    const key = await crypto.subtle.importKey(
      'raw',
      stringToArrayBuffer(secret),
      {name: 'HMAC', hash: 'SHA-256'},
      false,
      ['sign']
    );
    const computedSignature = await crypto.subtle.sign('HMAC', key, stringToArrayBuffer(input));

    return arrayBufferToHex(computedSignature);
  },
  secret => async (input, digest) => {
    const key = await crypto.subtle.importKey(
      'raw',
      stringToArrayBuffer(secret),
      {name: 'HMAC', hash: 'SHA-256'},
      false,
      ['sign']
    );
    const computedSignature = await crypto.subtle.sign('HMAC', key, stringToArrayBuffer(input));
    const signature = arrayBufferToHex(computedSignature);

    return timingSafeEqual(signature, digest);
  }
);

export const asymmetric = makeSecureWebhooks(
  priv => async input => {
    const decodedKey = atob(priv
      .replace("-----BEGIN PRIVATE KEY-----", '')
      .replace("-----END PRIVATE KEY-----", '')
      .replace(/\n/g, ''));

    // IMPORTANT: Test keys had to be converted to PKCS#8 because subtle crypto does not support PKCS#1
    const key = await crypto.subtle.importKey(
      'pkcs8',
      stringToUint8Array(decodedKey),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const computedSignature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, stringToArrayBuffer(input));
    return btoa(arrayBufferToString(computedSignature));
  },
  pub => async (input, digest) => {
    const decodedKey = atob(pub
      .replace("-----BEGIN PUBLIC KEY-----", '')
      .replace("-----END PUBLIC KEY-----", '')
      .replace(/\n/g, ''));

    const key = await crypto.subtle.importKey(
      'spki',
      stringToUint8Array(decodedKey),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );

    return await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      key,
      stringToArrayBuffer(atob(digest)),
      stringToArrayBuffer(input)
    );
  }
);

export const combined: SecureWebhooks = {
  sign: (input, secretOrPrivateKey, timestamp) =>
    secretOrPrivateKey.includes('PRIVATE KEY')
      ? asymmetric.sign(input, secretOrPrivateKey, timestamp)
      : symmetric.sign(input, secretOrPrivateKey, timestamp),
  verify: (input, secretOrPublicKey, signature, opts) =>
    secretOrPublicKey.includes('PUBLIC KEY')
      ? asymmetric.verify(input, secretOrPublicKey, signature, opts)
      : symmetric.verify(input, secretOrPublicKey, signature, opts),
};

export const sign = symmetric.sign;
export const verify = symmetric.verify;
