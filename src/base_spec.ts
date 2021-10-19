import { SecureWebhooks } from './base';

export function runTests(
  symmetric: SecureWebhooks,
  asymmetric: SecureWebhooks,
  mode: 'both' | 'only-pkcs8'
) {
  async function testWithKeyPair(
    swh: SecureWebhooks,
    pub: string,
    priv: string,
    expextedResult: string
  ) {
    const input = 'hello world';
    const timestamp = 1600000000000;
    const signature = await swh.sign(input, priv, timestamp);
    expect(signature).toEqual(expextedResult);

    // transmit input + signature over the wire

    const receivingTimestamp = timestamp + 60 * 1000;

    const isValidIfWithinTimeout = await swh.verify(input, pub, signature, {
      timestamp: receivingTimestamp,
    });
    expect(isValidIfWithinTimeout).toBe(true);

    const isValidIfOverTimeout = await swh.verify(input, pub, signature, {
      timestamp: receivingTimestamp,
      timeout: 0.5 * 60 * 1000,
    });
    expect(isValidIfOverTimeout).toBe(false);
  }

  test('symmetric', async () => {
    const secret = 'iamverysecret';
    await testWithKeyPair(
      symmetric,
      secret,
      secret,
      `v=1600000000000,d=3bd0b48300a7a7afc491e90ecef6805cb46813ea047434eed9cccc567f7aeecb`
    );
  });

  if (mode === 'both') {
    test('asymmetric (pkcs1)', async () => {
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

      await testWithKeyPair(
        asymmetric,
        publicKey,
        privateKey,
        `v=1600000000000,d=OwH2f2zKu8DHzCrlFKW36VzOZG6hmhtMCN5kVqX3BQTFkjPl7cri4Ar+yky0nyPNYfZG+Q1Kf3fithV8ufy+q25TZC2IXyhPpnytZTfKptlpLT3BGJ0Q1TMx1gQXrEFN2kzl1pH5ertxN1MwYuUnQCwfwigALKeaStADSZAJVVS25Tp+6DB8OrNpywjeruQZ6fUIWtWcF9q2O987zj+uUqya4GvUsa1NI9PFIXUb82e6ZXpw+0fqLNsHLYj60YqdCfeivxs3O+HGJekvqwJuj/bPCftbDBT4Cj4s5sjFYHtV3Rf2ERzu0ycIJD4BXC3oOyek1PX5lbaIRL7JwMpTWir98FjWEbSSlNbNeR/EEzVtKGwgWcEAlO33H4sBKhc1/OPKcAyMU8NFuudeUSrGSNzl9+qLIJkX+oFyct5iksZPbiyypI2NsrTZcY4W6yOpb5lq8gmNu+N2GfwkK57oL0Kj4q+zZuVrGFRQYTrgWVHbJhMhFpnIKGnFg71oIkfqxjn6dWesADVVgKyLoQ0ZE8E/2kc8Kt+pgPkun/ywMfyItOf9AyIgultGsKyQgPpS3aIioJLExuicNsci7brbXJXMo+grccV7GhgDnbGLn1uLrtE0zCh9d/Op0czWKRbLVzCPNAKIYW1+hkaTNROGs/Cu7vhOy7g766YtEX6EWpo=`
      );
    });
  }

  test('asymmetric', async () => {
    const publicKey = `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqmeVACnRiy7Em4TJ2hev
BQJek3ryctBaMQZKULAUg/+3Gk3CNgY/ZoWpFFlwnlIb60KuNAIIev8PEd63F3Ut
98UaiTiZnsqMN6j7SyPoSDMP5viFZN8pu+xwn6VoGS0y/7fGs8kV+4i96dh2ev0t
704E8l8CApVi607IN9NhaAgZrYHW4kTZb1UNcVSKYiG3U4J2e6HNeSIon4Ww7tdM
/6JEJWmKYybRzlGVDjZ5NYqRE+kTK1Dvlj525aJEVPy8AZzH53AwfIpukoz571vo
MKWgSypiyKPsXxs6AtaZfpWxLfz4VF0UlPr3Shf1CUls4llr6bFBRWub7YhQgiwF
14KkdmU/g5DnqiW8jG5P+D5suV8kLUaqtm47IfrGhb548/lrh6f9/fFgx+YXjweM
damh5jggjFPUGM3X7glIhl29v/js8HXyrFyuj97rS2G3ni36CAvTmZs4FCepmJAF
8EWFSUo4193mrFjuOeaWfGxqwUQ14W1TsHVEDWgptpO8RU3BNtP3dItY1iTbmIFG
2lisGb7ynitJ1vItme0Yd6MeelQjVRTi9vfHQawfm5D8kW6dT/ozKFMmffIphQkg
wa4xcerb9UQRMMMzgOy3HvQO2b7u0Wt/sm4IJlmI1/lBDYlcm4jt/69CvFw1C+3Z
2ud5X92lVG0AqFzycFCMyzUCAwEAAQ==
-----END PUBLIC KEY-----
  `.trim();
    const privateKey = `
-----BEGIN PRIVATE KEY-----
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
diGo3c5lzEb/84JXcGhvK9Uy4ck2F/M=
-----END PRIVATE KEY-----    
  `.trim();

    await testWithKeyPair(
      asymmetric,
      publicKey,
      privateKey,
      `v=1600000000000,d=OwH2f2zKu8DHzCrlFKW36VzOZG6hmhtMCN5kVqX3BQTFkjPl7cri4Ar+yky0nyPNYfZG+Q1Kf3fithV8ufy+q25TZC2IXyhPpnytZTfKptlpLT3BGJ0Q1TMx1gQXrEFN2kzl1pH5ertxN1MwYuUnQCwfwigALKeaStADSZAJVVS25Tp+6DB8OrNpywjeruQZ6fUIWtWcF9q2O987zj+uUqya4GvUsa1NI9PFIXUb82e6ZXpw+0fqLNsHLYj60YqdCfeivxs3O+HGJekvqwJuj/bPCftbDBT4Cj4s5sjFYHtV3Rf2ERzu0ycIJD4BXC3oOyek1PX5lbaIRL7JwMpTWir98FjWEbSSlNbNeR/EEzVtKGwgWcEAlO33H4sBKhc1/OPKcAyMU8NFuudeUSrGSNzl9+qLIJkX+oFyct5iksZPbiyypI2NsrTZcY4W6yOpb5lq8gmNu+N2GfwkK57oL0Kj4q+zZuVrGFRQYTrgWVHbJhMhFpnIKGnFg71oIkfqxjn6dWesADVVgKyLoQ0ZE8E/2kc8Kt+pgPkun/ywMfyItOf9AyIgultGsKyQgPpS3aIioJLExuicNsci7brbXJXMo+grccV7GhgDnbGLn1uLrtE0zCh9d/Op0czWKRbLVzCPNAKIYW1+hkaTNROGs/Cu7vhOy7g766YtEX6EWpo=`
    );
  });
}
