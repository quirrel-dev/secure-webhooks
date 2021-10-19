import { createHmac, createSign, createVerify } from 'crypto';
import { makeSecureWebhooks, SecureWebhooks } from './base';

export const symmetric = makeSecureWebhooks(
  secret => input =>
    createHmac('sha256', secret)
      .update(input)
      .digest('hex'),
  secret => (input, digest) =>
    createHmac('sha256', secret)
      .update(input)
      .digest('hex') === digest
);

export const asymmetric = makeSecureWebhooks(
  priv => input =>
    createSign('sha256')
      .update(input)
      .sign(priv, 'base64'),
  pub => (input, digest) =>
    createVerify('sha256')
      .update(input)
      .verify(pub, digest, 'base64')
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
