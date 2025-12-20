# pbotp-responder

This is a more full-featured responder for
[pbotp](https://github.com/florolf/pbotp). It's deployable as a container and
meant to run behind some kind of authorizing proxy like
[oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy).

All configuration happens via environment variables:

 - `PBOTP_LISTEN_ADDR` (optional, default `:8080`) - HTTP port/address to bind to
 - `PBOTP_PRIVKEY` - responder Ed25519 private key (base64url without padding)
 - `PBOTP_MODE` - `code` or `phrase`
 - `PBOTP_RESPONSE_LENGTH` - response length in digits (for `code`) or words (for `phrase`)
