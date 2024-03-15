import crypto from 'crypto';

// once you hash something, you can only compare it with hash value
export const hashString = (string: string) =>
  crypto.createHash('md5').update(string).digest('hex');
