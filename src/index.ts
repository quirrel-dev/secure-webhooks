import { createHmac, createSign, createVerify } from 'crypto';

function getHmac(secret: string) {
  return createHmac('sha256', secret);
}

function isPrivateKey(secretOrPrivateKey: string): boolean {
  return secretOrPrivateKey.includes('PRIVATE KEY');
}

function isPublicKey(secretOrPrivateKey: string): boolean {
  return secretOrPrivateKey.includes('PUBLIC KEY');
}

function verifyWithSecret(
  input: string,
  digest: string,
  secret: string
): boolean {
  return (
    getHmac(secret)
      .update(input)
      .digest('hex') === digest
  );
}

function signWithSecret(input: string, secret: string) {
  return getHmac(secret)
    .update(input)
    .digest('hex');
}

function getSigner(secretOrPrivateKey: string): (input: string) => string {
  if (isPrivateKey(secretOrPrivateKey)) {
    return v => signWithPrivate(v, secretOrPrivateKey);
  } else {
    return v => signWithSecret(v, secretOrPrivateKey);
  }
}

function signWithPrivate(input: string, priv: string): string {
  return createSign('sha256')
    .update(input)
    .sign(priv, 'base64');
}

function verifyWithPublic(input: string, digest: string, pub: string): boolean {
  return createVerify('sha256')
    .update(input)
    .verify(pub, digest, 'base64');
}

function getVerifier(
  secretOrPublicKey: string
): (input: string, digest: string) => boolean {
  if (isPublicKey(secretOrPublicKey)) {
    return (i, d) => verifyWithPublic(i, d, secretOrPublicKey);
  } else {
    return (i, d) => verifyWithSecret(i, d, secretOrPublicKey);
  }
}

export function sign(
  input: string,
  secretOrPrivateKey: string,
  timestamp: number = Date.now()
) {
  const signer = getSigner(secretOrPrivateKey);

  return `v=${timestamp},d=${signer(input + timestamp)}`;
}

const FIVE_MINUTES = 5 * 60 * 1000;

export function verify(
  input: string,
  secretOrPublicKey: string,
  signature: string,
  opts: { timeout?: number; timestamp?: number } = {}
) {
  const useBase64 = isPublicKey(secretOrPublicKey);
  const regex = useBase64
    ? /v=(\d+),d=((?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?)/
    : /v=(\d+),d=([\da-f]+)/;
  const match = regex.exec(signature);

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

  const verifier = getVerifier(secretOrPublicKey);

  return verifier(input + poststamp, postDigest);
}
