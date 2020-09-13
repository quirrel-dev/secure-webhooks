import { createHmac } from 'crypto';

function getHmac(secret: string) {
  return createHmac('sha256', secret);
}

export function sign(
  input: string,
  secret: string,
  timestamp: number = Date.now()
) {
  const hmac = getHmac(secret);

  hmac.update(input + timestamp);

  return `v=${timestamp},d=${hmac.digest('hex')}`;
}

const FIVE_MINUTES = 5 * 60 * 1000;

export function verify(
  input: string,
  secret: string,
  signature: string,
  opts: { timeout?: number; timestamp?: number } = {}
) {
  const match = /v=(\d+),d=([\da-f]+)/.exec(signature);
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

  const hmac = getHmac(secret);
  hmac.update(input + poststamp);

  return hmac.digest('hex') === postDigest;
}
