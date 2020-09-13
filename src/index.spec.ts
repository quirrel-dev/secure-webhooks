import { sign, verify } from './';

test('the whole flow', () => {
  const input = 'hello world';
  const secret = 'iamverysecret';
  const timestamp = 1600000000000;
  const signature = sign(input, secret, timestamp);
  expect(signature).toMatchInlineSnapshot(
    `"v=1600000000000,d=3bd0b48300a7a7afc491e90ecef6805cb46813ea047434eed9cccc567f7aeecb"`
  );

  // transmit input + signature over the wire

  const receivingTimestamp = timestamp + 60 * 1000;

  const isValidIfWithinTimeout = verify(input, secret, signature, {
    timestamp: receivingTimestamp,
  });
  expect(isValidIfWithinTimeout).toBe(true);

  const isValidIfOverTimeout = verify(input, secret, signature, {
    timestamp: receivingTimestamp,
    timeout: 0.5 * 60 * 1000,
  });
  expect(isValidIfOverTimeout).toBe(false);
});
