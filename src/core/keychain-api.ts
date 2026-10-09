/**
 * Method names on the `keytar` / `keychain` modules that touch secret material.
 * Capability chips and secret-touch "api" rows use the full call set; value
 * reads that feed the creds-network red line use a read set.
 *
 * Do not match `keychain.\w+`: a local Set named `keychain` with `.add` / `.has`
 * is not OS keychain access.
 */

/**
 * Library reads matched by bare receiver name (`keytar.getPassword(`). The
 * name alone does not prove the module, so this stays to real library APIs:
 * a local `keychain` object with `getToken()` must not red-line.
 */
export const KEYCHAIN_BARE_READ_METHODS =
  'getPassword|getCredentials|findCredentials|findPassword'

/**
 * Reads through a receiver bound to a `keytar` / `keychain` import, where the
 * module is proven and wrapper method names are also treated as reads.
 */
export const KEYCHAIN_READ_METHODS =
  `${KEYCHAIN_BARE_READ_METHODS}|getSecret|getToken|findAnyCredential`

/** Calls that write or delete secret values. */
export const KEYCHAIN_WRITE_METHODS =
  'setPassword|deletePassword|setCredentials|deleteCredentials'

/** Any method that counts as credential / secret access. */
export const KEYCHAIN_CALL_METHODS = `${KEYCHAIN_READ_METHODS}|${KEYCHAIN_WRITE_METHODS}`

/**
 * Capability match on `keytar.<method>` / `keychain.<method>`, also via
 * `.default`. No trailing `(`: `promisify(keytar.findPassword)` and
 * `keytar.getPassword.bind(…)` are access too; the method allow-list is what
 * keeps `keychain.add` on a Set out.
 */
export const KEYCHAIN_MEMBER_SOURCE =
  String.raw`\b(?:keychain|keytar)\.(?:default\.)?(?:${KEYCHAIN_CALL_METHODS})\b`
