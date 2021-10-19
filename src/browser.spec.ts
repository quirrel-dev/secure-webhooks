import { Crypto } from '@peculiar/webcrypto';
import { runTests } from './base_spec';
import { symmetric, asymmetric } from './browser';

// Emulate a browser environment and polyfill WebCrypto, TextEncoder
// @ts-ignore
window.crypto = new Crypto();

runTests(symmetric, asymmetric, 'only-pkcs8');
