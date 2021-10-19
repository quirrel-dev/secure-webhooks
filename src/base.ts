const FIVE_MINUTES = 5 * 60 * 1000;

export function makeSecureWebhooks(
  getSigner: (secretOrPrivateKey: string) => (input: string) => string,
  getVerifier: (
    secretOrPublicKey: string
  ) => (input: string, digest: string) => boolean
) {
  return {
    sign(
      input: string,
      secretOrPrivateKey: string,
      timestamp: number = Date.now()
    ): string {
      const signer = getSigner(secretOrPrivateKey);

      return `v=${timestamp},d=${signer(input + timestamp)}`;
    },
    verify(
      input: string,
      secret: string,
      signature: string,
      opts: { timeout?: number; timestamp?: number } = {}
    ): boolean {
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
