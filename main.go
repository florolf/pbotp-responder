package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"

	bip39 "github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/blake2s"
)

type Mode string
const (
	ModeCode   Mode = "code"
	ModePhrase Mode = "phrase"
)

type Responder struct {
	privKey *ecdh.PrivateKey
	mode    Mode
	length  int
}

func NewResponder(privKeyBytes []byte, mode Mode, length int) (*Responder, error) {
	var err error

	var privKey *ecdh.PrivateKey
	if privKey, err = ecdh.X25519().NewPrivateKey(privKeyBytes); err != nil {
		return nil, fmt.Errorf("failed to create private key: %v", err)
	}

	var lengthMax int
	switch mode {
	case ModeCode:
		lengthMax = 19
	case ModePhrase:
		lengthMax = 23
	}

	if length <= 0 {
		return nil, fmt.Errorf("invalid length %d; must be > 0", length)
	}
	if length > lengthMax {
		return nil, fmt.Errorf("invalid length %d; must be < %d for %s", length, lengthMax, mode)
	}

	return &Responder{
		privKey: privKey,
		mode:    mode,
		length:  length,
	}, nil
}

func (r *Responder) Response(payload []byte, challenge []byte, length int) (string, error) {
	var err error

	var pubKey *ecdh.PublicKey
	if pubKey, err = ecdh.X25519().NewPublicKey(challenge); err != nil {
		return "", fmt.Errorf("loading challenge: %v", err)
	}

	dhSecret, err := r.privKey.ECDH(pubKey)
	if err != nil {
		return "", fmt.Errorf("x25519: %w", err)
	}

	h, err := blake2s.New256(dhSecret)
	if err != nil {
		return "", fmt.Errorf("blake2s: %w", err)
	}
	_, _ = h.Write([]byte("de.n621.pbotp.v2\x00"))
	_, _ = h.Write(payload)
	sig := h.Sum(nil)

	switch r.mode {
	case ModeCode:
		return formatCodeNumeric(sig, r.length)
	case ModePhrase:
		return formatCodeBIP39(sig, r.length)
	default:
		return "", fmt.Errorf("unsupported mode: %q", r.mode)
	}
}

func (r *Responder) PublicKey() []byte {
	return r.privKey.PublicKey().Bytes()
}

func formatCodeNumeric(sig []byte, length int) (string, error) {
	P := binary.LittleEndian.Uint64(sig[:8])

	var modulus uint64 = 1
	for i := 0; i < length; i++ {
		modulus *= 10
	}
	codeVal := P % modulus

	raw := fmt.Sprintf("%0*d", length, codeVal)

	groupSize := 0
	for _, candidate := range []int{5, 4, 3} {
		if length%candidate == 0 {
			groupSize = candidate
			break
		}
	}

	var b strings.Builder
	for i, r := range raw {
		if i > 0 && (len(raw)-i) % groupSize == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String(), nil
}

func formatCodeBIP39(sig []byte, length int) (string, error) {

	rev := make([]byte, len(sig))
	for i := range sig {
		rev[len(sig)-1-i] = sig[i]
	}
	n := new(big.Int).SetBytes(rev)

	mask := big.NewInt(2048 - 1)
	words := make([]string, length)

	var bip39WordList = bip39.GetWordList()
	idx := new(big.Int)
	for i := 0; i < length; i++ {
		idx.And(n, mask)
		idxVal := idx.Int64()
		if idxVal < 0 || idxVal >= int64(len(bip39WordList)) {
			return "", errors.New("bip39 index out of range")
		}
		words[i] = bip39WordList[idxVal]
		n.Rsh(n, 11)
	}

	return strings.Join(words, " "), nil
}

type Config struct {
	ListenAddr     string
	PrivKey        []byte
	Mode           Mode
	ResponseLength int
}

func configFromEnv() (*Config, error) {
	cfg := &Config{
		ListenAddr: ":8080",
	}

	if v := os.Getenv("PBOTP_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}

	var privKeyB64 string
	var envSet bool
	if privKeyB64, envSet = os.LookupEnv("PBOTP_PRIVKEY"); !envSet {
		return nil, fmt.Errorf("PBOTP_PRIVKEY is required")
	}

	var err error
	if cfg.PrivKey, err = base64.RawURLEncoding.DecodeString(privKeyB64); err != nil {
		log.Fatalf("failed to decode PBOTP_PRIVKEY: %v", err)
	}

	var modeStr string
	if modeStr, envSet = os.LookupEnv("PBOTP_MODE"); !envSet {
		return nil, fmt.Errorf("PBOTP_MODE is required")
	}
	switch strings.ToLower(modeStr) {
	case "code":
		cfg.Mode = ModeCode
	case "phrase":
		cfg.Mode = ModePhrase
	default:
		return nil, fmt.Errorf("invalid PBOTP_MODE: %q (expected \"code\" or \"phrase\")", modeStr)
	}

	var lengthStr string
	if lengthStr, envSet = os.LookupEnv("PBOTP_RESPONSE_LENGTH"); !envSet {
		return nil, fmt.Errorf("PBOTP_RESPONSE_LENGTH is required")
	}

	if cfg.ResponseLength, err = strconv.Atoi(lengthStr); err != nil {
		return nil, fmt.Errorf("invalid PBOTP_RESPONSE_LENGTH: %v", err)
	}

	return cfg, nil
}

func makeHandler(responder *Responder, cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.Trim(r.URL.Path, "/")
		if path == "" {
			pubKeyB64 := base64.RawURLEncoding.EncodeToString(responder.PublicKey())
			_, _ = fmt.Fprintf( w, "pbotp v2\npublic key: %s\n", pubKeyB64)
			return
		}

		parts := strings.Split(path, "/")
		if len(parts) != 4 {
			http.NotFound(w, r)
			return
		}

		group := parts[0]
		node := parts[1]
		user := parts[2]
		challengeB64 := parts[3]

		challenge, err := base64.RawURLEncoding.DecodeString(challengeB64)
		if err != nil {
			http.Error(w, "invalid challenge encoding", http.StatusBadRequest)
			return
		}
		payload := []byte(group + "\x00" + node + "\x00" + user + "\x00")

		resp, err := responder.Response(payload, challenge, cfg.ResponseLength)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		responseTemplate.Execute(w, struct {
			Node string
			Code string
			Mode string
		}{
			Node: node,
			Code: resp,
			Mode: string(cfg.Mode),
		})
	}
}

func main() {
	cfg, err := configFromEnv()
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	responder, err := NewResponder(cfg.PrivKey, cfg.Mode, cfg.ResponseLength)
	if err != nil {
		log.Fatalf("failed to create responder: %v", err)
	}

	http.HandleFunc("/", makeHandler(responder, cfg))

	log.Printf("listening on %s (mode=%s, response_length=%d)", cfg.ListenAddr, cfg.Mode, cfg.ResponseLength)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, nil))
}

var responseTemplate = template.Must(template.New("response").Parse(`
<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width">

		<title>Login token for {{ .Node }}</title>

		<style>
			html, body {
				height: 100%;
				margin: 0;
				padding: 0;
				border: 0;
			}

			body {
				background-color: #369;
			}

			.container {
				display: flex;
				align-items: center;
				justify-content: center;
				height: 100%;
			}

			.box {
				border-radius: 30px;
				background-color: #d7d7d7;
				text-align: center;

				padding: 40px;
			}

			.box .code {
				font-family: monospace;
				font-size: 40pt;
				word-spacing: -10pt;
				margin: 0px;
			}

			.box .phrase {
				font-size: 40pt;
				margin: 0px;
			}
		</style>
	</head>
	<body>
		<div class="container">
			<div class="box">
				<p>Login token for <b>{{ .Node }}</b>:</p>
				<p class="{{ .Mode }}">{{ .Code }}</p>
			</div>
		</div>

	</body>
</html>
`))
