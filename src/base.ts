const FIVE_MINUTES = 5 * 60 * 1000;

export function makeSecureWebhooks(
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

      return await verifier(input + poststamp, postDigest);
    },
  };
}

export type SecureWebhooks = ReturnType<typeof makeSecureWebhooks>;
