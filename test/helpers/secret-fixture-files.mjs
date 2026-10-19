// The secret files of the secrets fixture. They are not versioned: SEC-03 judges file names, so a versioned
// file named .env or *.pem is a high finding even when its values are fake. The tests that use the fixture write
// these files into the temp copy, on top of the versioned files, with the files option of make-fixture.mjs.
//
// The values are placeholders with no token-shaped text. test/secrets.test.mjs checks them.

export const SECRET_FIXTURE_FILES = Object.freeze({
  ".env": "# Placeholder values for the secrets fixture. The scanner must never read this file.\nAPP_NAME=fixture\n",
  "config/server.pem": "placeholder, not a certificate\n",
});
