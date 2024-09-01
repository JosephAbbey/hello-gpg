import { CredentialStore } from 'node-ms-passport';
import { KeyCreationOption, Passport } from 'passport-desktop';
import password from '@inquirer/password';

/** polyfill */
async function requestVerification(id: string): Promise<boolean> {
  if (!Passport.available()) {
    return false;
  }
  const passport = new Passport(id);
  try {
    await passport.createAccount(KeyCreationOption.ReplaceExisting);
    // await passport.sign(Buffer.alloc(30, 10));
    return true;
  } catch {
    return false;
  }
}

try {
  switch (Bun.argv[2]) {
    case 'setup': {
      //TODO: setup
      // save old gpg location and `git config --set gpg.program ${self}`
      break;
    }
    case 'save': {
      const id = Bun.argv[3];

      if (!(await requestVerification(id))) {
        throw new Error('Failed to verify identity');
      }

      const store = new CredentialStore(`gpg/${id}`, false);

      if (await store.exists()) {
        throw new Error(`Credential with ID ${id} already exists`);
      }

      const passphrase = await password({
        message: `Enter passphrase for credential ${id}`,
      });

      await store.write(id, passphrase);

      break;
    }
    case 'remove': {
      const id = Bun.argv[3];

      if (!(await requestVerification(id))) {
        throw new Error('Failed to verify identity');
      }

      const store = new CredentialStore(`gpg/${id}`, false);

      if (!(await store.exists())) {
        throw new Error(`Credential with ID ${id} does not exist`);
      }

      await store.remove();

      break;
    }
    case '-bsau': {
      const id = Bun.argv[3];

      // Doesn't seem to work
      // const result = await Passport.requestVerification('Verify your identity');
      // if (result === VerificationResult.Verified) {
      // Just use the passport constructor to check
      if (await requestVerification(id)) {
        const store = new CredentialStore(`gpg/${id}`, false);

        if (await store.exists()) {
          const credential = await store.read();
          await credential.loadPassword();
          const passphrase = credential.password;
          await credential.unloadPassword();

          if (passphrase) {
            try {
              const { stdout, stderr } =
                await Bun.$`"C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe" --pinentry-mode loopback --passphrase ${passphrase} -bsau ${Bun.argv.slice(3)} < ${Bun.stdin}`;
              process.stdout.write(stdout.toString());
              process.stderr.write(stderr.toString());
              break;
            } catch (e) {
              const error = e;
              //@ts-expect-error
              process.exit(error.exitCode);
            }
            //! Fallthrough if error
          }
          //! Fallthrough if we don't have the passphrase
        }
        //! Fallthrough if we don't have the credential
      }
      //-! Fallthrough if verification failed
    }
    default:
      // Not for us, send to gpg
      try {
        const { stdout, stderr } =
          await Bun.$`"C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe" ${Bun.argv.slice(2)} < ${Bun.stdin}`;
        process.stdout.write(stdout.toString());
        process.stderr.write(stderr.toString());
      } catch (e) {
        const error = e;
        //@ts-expect-error
        process.exit(error.exitCode);
      }
      break;
  }
} catch (e) {
  const error = e;
  //@ts-expect-error
  console.error(error.message);
  process.exit(1);
}
