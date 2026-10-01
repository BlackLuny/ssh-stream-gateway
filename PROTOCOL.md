# Stream protocol v1

Transport is TLS with ALPN `h2`, one HTTP/2 `POST /v1/exec`. Both request and successful response have `Content-Type: application/vnd.ssh-stream.v1`. Request authentication is `Authorization: Bearer <passphrase>`; printable ASCII spaces inside the passphrase are significant. The client does not follow redirects or replay requests. Non-2xx responses mean the request was rejected; no SSH child is created for authentication, framing, target or capacity rejection. A 502 spawn failure also creates no child.

Each frame is kind (one byte), payload length (four bytes, unsigned big endian), then exactly that many payload bytes. Maximum payload is 16384 bytes. An oversized/truncated or wrong-direction frame is an error. Frames can cross HTTP DATA boundaries.

## Request

- 1 OPEN: first and exactly once. UTF-8 JSON object with `target` and `command` strings. Unknown keys rejected. Target is a configured alias, command is nonempty, no NUL, max 8192 bytes (and the encoded JSON must fit a frame)
- 2 STDIN: nonempty raw bytes before EOF
- 3 EOF: empty; at most once. Closes the SSH stdin pipe but does not close stdout/stderr
- 4 CANCEL: empty. Terminates the local SSH child; best effort if queued behind blocked stdin. For prompt cancellation reset/drop the response stream/connection

An HTTP request end before explicit EOF is invalid. After EOF the client can leave the request open (to send CANCEL) or end it. Ending the request after EOF does not cancel output. Duplicate EOF, repeated OPEN, empty STDIN, data after EOF or unknown types abort the session. If the SSH child stops accepting stdin early, the gateway stops processing stdin and waits for output/exit; response reset and timeouts can still cancel it.

## Response

- 17 STDOUT: nonempty raw bytes
- 18 STDERR: nonempty raw bytes
- 19 EXIT: JSON `{"code": 0, "error": null}`, always last when transport still permits it

Output within each stream is ordered; cross-stream ordering is not guaranteed. Remote SSH status is preserved (0–255), including OpenSSH's conventional connection error 255. When local SSH dies by signal, 255 is used. Gateway timeout uses 124; stream/cancel/shutdown failures use 125 and a machine-readable error string. Client Ctrl-C uses 130. Exit codes overlap with valid remote programs, so use `error` when consuming the protocol directly.

No EXIT means outcome unknown, not success. If a client disconnects, a final EXIT cannot necessarily be delivered. Cancellation kills/reaps local SSH, without promising cancellation of remote detached processes.

## Resource limits

Defaults: four sessions, 3600-second wall lifetime and 300-second no-progress timeout, configurable within bounded limits. Server allows 32 TCP/TLS connections, up to four HTTP/2 streams per connection and 8192 bytes of request headers. TLS handshake timeout 10 seconds; authenticated opening frame timeout 10 seconds. Application queues hold eight frames per direction; each frame at most 16 KiB. HTTP/2 windows and send buffers are bounded. Socket and OpenSSH OS buffers add bounded overhead. Authentication is globally rate-limited; Retry-After on 429 is 12 seconds. Success refunds an attempt; slow/failed Argon2 checks use two bounded slots.

TLS verification occurs for both HTTPS proxies and origin. HTTP CONNECT parser permits only 2xx, limits headers to 16 KiB and preserves tunnel bytes coalesced after the header. A proxy can deny availability but cannot read bearer/command/data without being trusted for origin TLS interception. Explicitly adding a CA therefore expands TLS trust and must be an operator decision.
