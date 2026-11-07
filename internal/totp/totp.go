// Package totp genera códigos de un solo uso según RFC 6238 y RFC 4226.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"time"
)

// Algoritmos admitidos.
const (
	SHA1   = "SHA1"
	SHA256 = "SHA256"
	SHA512 = "SHA512"
)

// Code devuelve el código TOTP para el instante t.
func Code(secret []byte, t time.Time, period, digits int, algo string) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("totp: secreto vacío")
	}
	if err := validatePeriod(period); err != nil {
		return "", err
	}
	if t.Unix() < 0 {
		return "", errors.New("totp: tiempo anterior a 1970")
	}

	var modulus uint32
	switch digits {
	case 6:
		modulus = 1_000_000
	case 8:
		modulus = 100_000_000
	default:
		return "", fmt.Errorf("totp: dígitos no admitidos: %d", digits)
	}

	var newHash func() hash.Hash
	switch algo {
	case SHA1:
		newHash = sha1.New
	case SHA256:
		newHash = sha256.New
	case SHA512:
		newHash = sha512.New
	default:
		return "", fmt.Errorf("totp: algoritmo no admitido: %q", algo)
	}

	counter := uint64(t.Unix()) / uint64(period)

	mac := hmac.New(newHash, secret)
	mac.Write(binary.BigEndian.AppendUint64(nil, counter))
	sum := mac.Sum(nil)

	// Truncamiento dinámico de RFC 4226, sección 5.3.
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:]) & 0x7fffffff

	return fmt.Sprintf("%0*d", digits, value%modulus), nil
}

// Remaining devuelve los segundos que le quedan al periodo que contiene a t.
func Remaining(t time.Time, period int) (int, error) {
	if err := validatePeriod(period); err != nil {
		return 0, err
	}
	if t.Unix() < 0 {
		return 0, errors.New("totp: tiempo anterior a 1970")
	}
	return period - int(t.Unix()%int64(period)), nil
}

func validatePeriod(period int) error {
	if period <= 0 {
		return fmt.Errorf("totp: periodo no válido: %d", period)
	}
	return nil
}
