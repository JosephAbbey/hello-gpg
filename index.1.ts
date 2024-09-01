//@ts-nocheck
// A failed attempt...

import { $, argv, CryptoHasher, ShellError, stdin } from 'bun';
import { Passport } from 'passport-desktop';
import { armor } from 'openpgp';

switch (argv[2]) {
  case '-bsau': {
    if (!Passport.available()) {
      throw new Error('Windows Hello is not available');
    }

    const key = argv[3];
    const passport = new Passport(key);

    if (!passport.accountExists) {
      throw new Error(`Credential with ID ${key} does not exist`);
    }

    const data = await stdin.bytes();

    const hasher = new CryptoHasher('sha256');
    hasher.update(data);
    const sig = await passport.sign(hasher.digest());

    process.stdout.write(armor(6, sig));
    //                         ^ enums.armor.signature
    break;
  }
  case 'create': {
    if (!Passport.available()) {
      throw new Error('Windows Hello is not available');
    }

    const key = argv[3];
    const passport = new Passport(key);

    if (passport.accountExists) {
      throw new Error(`Credential with ID ${key} already exists`);
    }

    await passport.createAccount();

    const pub = await passport.getPublicKey();

    process.stdout.write(armor(4, pub));
    //                         ^ enums.armor.publicKey
    break;
  }
  case 'export': {
    if (!Passport.available()) {
      throw new Error('Windows Hello is not available');
    }

    const key = argv[3];
    const passport = new Passport(key);

    if (!passport.accountExists) {
      throw new Error(`Credential with ID ${key} does not exist`);
    }

    const pub = await passport.getPublicKey();

    process.stdout.write(armor(4, pub));
    //                         ^ enums.armor.publicKey
    break;
  }
  case 'delete': {
    if (!Passport.available()) {
      throw new Error('Windows Hello is not available');
    }

    const key = argv[3];
    const passport = new Passport(key);

    if (!passport.accountExists) {
      throw new Error(`Credential with ID ${key} does not exist`);
    }

    await passport.deleteAccount();
    break;
  }
  default:
    // Not for us, send to gpg
    try {
      const { stdout, stderr } =
        await $`"C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe" ${argv.slice(2)} < ${stdin}`;
      process.stdout.write(stdout.toString());
      process.stderr.write(stderr.toString());
    } catch (e) {
      const error = e as ShellError;
      process.exit(error.exitCode);
    }
    break;
}
