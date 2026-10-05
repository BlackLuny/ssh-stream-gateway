# Linux client setup and recovery helpers

Source snapshot: 2026-10-05. These optional Python helpers wrap this repository's
Rust client. They use Linux `/proc/self/fd`, owner-only files, a verified binary
checksum, hidden interactive entry, a bounded hostname probe, and atomic
no-overwrite credential retention. No installed client, real configuration,
credential, certificate, runtime log, or remote output is included.

## Build and configure

Requirements: Linux, Python 3.10+ (tested with 3.12), and the Rust client's build
requirements from the root README. Build the client with `cargo build --locked
--release`. Copy only these helper source files and the freshly built binary to
a new user-owned directory outside the checkout. Make the directory mode 0700
and initially keep the binary mode 0600.

Edit `gateway_common.py` in that private installed copy, not in Git:

- `ENDPOINT`: your existing, trusted HTTPS gateway URL
- `TARGET`: an already-configured server-side target alias
- `EXPECTED_HOST`: the exact expected `hostname` output as bytes
- `BINARY_SHA256`: the SHA256 of the binary whose source/build you verified

The distributed example endpoint is intentionally non-routable; the checksum
placeholder intentionally fails verification. Never disable checksum, TLS or
SSH host-key verification. The example hostname/alias are not production values.
Do not store any password in source, arguments or environment variables.

## User-run setup

From an interactive terminal in the private installed directory, run:

    python3 setup-client.py

Read the destination and retention notice. Type `SAVE AND TEST` only if you
intend to activate this exact binary and retain an existing passphrase locally.
Enter the passphrase through the hidden terminal prompt, never through chat or
a pipe. Only the expected successful hostname response with no stderr retains
`.private/password`. The helper does not create a server account, credential,
OAuth grant, SSH trust entry or network rule. The person operating it owns those
separate authorization decisions.

For separately authorized remote work:

    python3 gateway-exec 'one remote command string'

Stdin passes through. A command is not replayed after failure; an interrupted
remote command can have an unknown result. Confirm its outcome before retrying.

## Recovery

Normal failure/cancellation and SIGINT/SIGTERM/SIGHUP remove the newly created
pending file. SIGKILL or a machine crash can leave `.private/.pending-*` files;
a subsequent setup deliberately refuses to proceed. Inspect metadata locally,
without printing or uploading contents; determine whether a prior operation
completed before an explicitly authorized local cleanup. Existing retained
credentials are never overwritten by this helper. Keep private files out of
backups, archives and Git. Recreate a missing client from a verified build rather
than copying another machine's credentials.

## Tests and limits

    python3 -m unittest -v test_restore
    python3 -O -m unittest -v test_restore

Both commands passed 21 synthetic tests on 2026-10-05 after replacing all
installation-specific endpoint/alias/hostname/checksum values. Fixtures use
temporary files and mock subprocesses; no real gateway or credential is used.
These tests do not establish real deployment connectivity, authentication or
remote cancellation. Python cannot guarantee secure memory erasure. This
publication adds no new license grant and does not change existing repository
licensing; dependency licenses remain applicable.
