import { SecureWebhooks, symmetric, asymmetric } from './';

function testWithKeyPair(
  swh: SecureWebhooks,
  pub: string,
  priv: string,
  expextedResult: string
) {
  const input = 'hello world';
  const timestamp = 1600000000000;
  const signature = swh.sign(input, priv, timestamp);
  expect(signature).toEqual(expextedResult);

  // transmit input + signature over the wire

  const receivingTimestamp = timestamp + 60 * 1000;

  const isValidIfWithinTimeout = swh.verify(input, pub, signature, {
    timestamp: receivingTimestamp,
  });
  expect(isValidIfWithinTimeout).toBe(true);

  const isValidIfOverTimeout = swh.verify(input, pub, signature, {
    timestamp: receivingTimestamp,
    timeout: 0.5 * 60 * 1000,
  });
  expect(isValidIfOverTimeout).toBe(false);
}

test('symmetric', () => {
  const secret = 'iamverysecret';
  testWithKeyPair(
    symmetric,
    secret,
    secret,
    `v=1600000000000,d=3bd0b48300a7a7afc491e90ecef6805cb46813ea047434eed9cccc567f7aeecb`
  );
});

test('asymmetric', () => {
  const publicKey = `
-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAqmeVACnRiy7Em4TJ2hevBQJek3ryctBaMQZKULAUg/+3Gk3CNgY/
ZoWpFFlwnlIb60KuNAIIev8PEd63F3Ut98UaiTiZnsqMN6j7SyPoSDMP5viFZN8p
u+xwn6VoGS0y/7fGs8kV+4i96dh2ev0t704E8l8CApVi607IN9NhaAgZrYHW4kTZ
b1UNcVSKYiG3U4J2e6HNeSIon4Ww7tdM/6JEJWmKYybRzlGVDjZ5NYqRE+kTK1Dv
lj525aJEVPy8AZzH53AwfIpukoz571voMKWgSypiyKPsXxs6AtaZfpWxLfz4VF0U
lPr3Shf1CUls4llr6bFBRWub7YhQgiwF14KkdmU/g5DnqiW8jG5P+D5suV8kLUaq
tm47IfrGhb548/lrh6f9/fFgx+YXjweMdamh5jggjFPUGM3X7glIhl29v/js8HXy
rFyuj97rS2G3ni36CAvTmZs4FCepmJAF8EWFSUo4193mrFjuOeaWfGxqwUQ14W1T
sHVEDWgptpO8RU3BNtP3dItY1iTbmIFG2lisGb7ynitJ1vItme0Yd6MeelQjVRTi
9vfHQawfm5D8kW6dT/ozKFMmffIphQkgwa4xcerb9UQRMMMzgOy3HvQO2b7u0Wt/
sm4IJlmI1/lBDYlcm4jt/69CvFw1C+3Z2ud5X92lVG0AqFzycFCMyzUCAwEAAQ==
-----END RSA PUBLIC KEY-----
`.trim();
  const privateKey = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`.trim();

  testWithKeyPair(
    asymmetric,
    publicKey,
    privateKey,
    `v=1600000000000,d=OwH2f2zKu8DHzCrlFKW36VzOZG6hmhtMCN5kVqX3BQTFkjPl7cri4Ar+yky0nyPNYfZG+Q1Kf3fithV8ufy+q25TZC2IXyhPpnytZTfKptlpLT3BGJ0Q1TMx1gQXrEFN2kzl1pH5ertxN1MwYuUnQCwfwigALKeaStADSZAJVVS25Tp+6DB8OrNpywjeruQZ6fUIWtWcF9q2O987zj+uUqya4GvUsa1NI9PFIXUb82e6ZXpw+0fqLNsHLYj60YqdCfeivxs3O+HGJekvqwJuj/bPCftbDBT4Cj4s5sjFYHtV3Rf2ERzu0ycIJD4BXC3oOyek1PX5lbaIRL7JwMpTWir98FjWEbSSlNbNeR/EEzVtKGwgWcEAlO33H4sBKhc1/OPKcAyMU8NFuudeUSrGSNzl9+qLIJkX+oFyct5iksZPbiyypI2NsrTZcY4W6yOpb5lq8gmNu+N2GfwkK57oL0Kj4q+zZuVrGFRQYTrgWVHbJhMhFpnIKGnFg71oIkfqxjn6dWesADVVgKyLoQ0ZE8E/2kc8Kt+pgPkun/ywMfyItOf9AyIgultGsKyQgPpS3aIioJLExuicNsci7brbXJXMo+grccV7GhgDnbGLn1uLrtE0zCh9d/Op0czWKRbLVzCPNAKIYW1+hkaTNROGs/Cu7vhOy7g766YtEX6EWpo=`
  );
});
