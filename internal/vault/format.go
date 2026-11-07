package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Formato del archivo, con enteros en big endian:
//
//	magic (4) | versión (1) | tiempo (4) | memoria en KiB (4) | hilos (1) | sal (16)
//	nonce (24) | texto cifrado + tag
//
// Todo lo anterior al nonce es la cabecera, que se autentica como AAD.
const (
	magic         = "PK2F"
	formatVersion = 1

	saltSize   = 16
	headerSize = len(magic) + 1 + 4 + 4 + 1 + saltSize
	minSize    = headerSize + chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead
)

// Límites de Argon2id admitidos al leer un archivo. Los parámetros se usan
// antes de poder autenticarlos: sin límites, un archivo alterado podría agotar
// la memoria o hacer que argon2 entre en pánico.
const (
	minTime      = 1
	maxTime      = 10
	minThreads   = 1
	maxThreads   = 16
	minMemoryKiB = 32 * 1024
	maxMemoryKiB = 1024 * 1024
)

type kdfParams struct {
	time      uint32
	memoryKiB uint32
	threads   uint8
}

var defaultParams = kdfParams{time: 3, memoryKiB: 64 * 1024, threads: 4}

func (p kdfParams) valid() bool {
	return p.time >= minTime && p.time <= maxTime &&
		p.memoryKiB >= minMemoryKiB && p.memoryKiB <= maxMemoryKiB &&
		p.threads >= minThreads && p.threads <= maxThreads
}

func deriveKey(password, salt []byte, p kdfParams) []byte {
	return argon2.IDKey(password, salt, p.time, p.memoryKiB, p.threads, chacha20poly1305.KeySize)
}

// seal cifra plaintext con una sal y un nonce nuevos.
func seal(password []byte, p kdfParams, plaintext []byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("vault: generar la sal: %w", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault: generar el nonce: %w", err)
	}

	key := deriveKey(password, salt, p)
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("vault: iniciar el cifrado: %w", err)
	}

	out := make([]byte, 0, minSize+len(plaintext))
	out = append(out, magic...)
	out = append(out, formatVersion)
	out = binary.BigEndian.AppendUint32(out, p.time)
	out = binary.BigEndian.AppendUint32(out, p.memoryKiB)
	out = append(out, p.threads)
	out = append(out, salt...)
	header := out[:headerSize]

	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, header), nil
}

// unseal valida la cabecera, deriva la clave y descifra. Cualquier fallo que
// pueda deberse a la contraseña o a una alteración devuelve ErrInvalid.
func unseal(password, data []byte) ([]byte, error) {
	if len(data) <= len(magic) || !bytes.HasPrefix(data, []byte(magic)) {
		return nil, ErrInvalid
	}
	if data[len(magic)] != formatVersion {
		return nil, ErrUnsupportedVersion
	}
	if len(data) < minSize {
		return nil, ErrInvalid
	}

	rest := data[len(magic)+1:]
	p := kdfParams{
		time:      binary.BigEndian.Uint32(rest[0:4]),
		memoryKiB: binary.BigEndian.Uint32(rest[4:8]),
		threads:   rest[8],
	}
	if !p.valid() {
		return nil, ErrInvalid
	}
	salt := rest[9 : 9+saltSize]

	key := deriveKey(password, salt, p)
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrInvalid
	}

	header := data[:headerSize]
	nonce := data[headerSize : headerSize+chacha20poly1305.NonceSizeX]
	plaintext, err := aead.Open(nil, nonce, data[headerSize+chacha20poly1305.NonceSizeX:], header)
	if err != nil {
		return nil, ErrInvalid
	}
	return plaintext, nil
}
