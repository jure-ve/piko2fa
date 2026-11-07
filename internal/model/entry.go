// Package model define las cuentas 2FA que guarda el vault.
package model

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"piko2fa/internal/totp"
)

// Valores por defecto de una cuenta y único tipo admitido en v1.
const (
	DefaultAlgorithm = totp.SHA1
	DefaultDigits    = 6
	DefaultPeriod    = 30
	TypeTOTP         = "totp"
)

// Entry es una cuenta 2FA.
type Entry struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Issuer    string    `json:"issuer"`
	Secret    []byte    `json:"secret"`
	Algorithm string    `json:"algorithm"`
	Digits    int       `json:"digits"`
	Period    int       `json:"period"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
}

// New crea una cuenta TOTP válida, con ID y fecha de creación nuevos.
func New(name, issuer string, secret []byte, algorithm string, digits, period int) (Entry, error) {
	e := Entry{
		ID:        newID(),
		Name:      name,
		Issuer:    issuer,
		Secret:    secret,
		Algorithm: algorithm,
		Digits:    digits,
		Period:    period,
		Type:      TypeTOTP,
		CreatedAt: time.Now().UTC(),
	}
	if err := e.Validate(); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// Validate comprueba que la cuenta permita generar códigos.
func (e Entry) Validate() error {
	if e.Name == "" && e.Issuer == "" {
		return errors.New("cuenta sin nombre ni emisor")
	}
	if len(e.Secret) == 0 {
		return errors.New("cuenta sin secreto")
	}
	switch e.Algorithm {
	case totp.SHA1, totp.SHA256, totp.SHA512:
	default:
		return errors.New("algoritmo no admitido")
	}
	if e.Digits != 6 && e.Digits != 8 {
		return errors.New("número de dígitos no admitido")
	}
	if e.Period <= 0 {
		return errors.New("periodo no válido")
	}
	if e.Type != TypeTOTP {
		return errors.New("tipo de cuenta no admitido")
	}
	return nil
}

// Label devuelve el nombre con el que se muestra la cuenta: "Emisor:cuenta".
func (e Entry) Label() string {
	switch {
	case e.Issuer == "":
		return e.Name
	case e.Name == "":
		return e.Issuer
	default:
		return e.Issuer + ":" + e.Name
	}
}

// String omite el secreto, para que no aparezca al imprimir una cuenta.
func (e Entry) String() string {
	return fmt.Sprintf("Entry{ID:%s Issuer:%q Name:%q Algorithm:%s Digits:%d Period:%d Type:%s}",
		e.ID, e.Issuer, e.Name, e.Algorithm, e.Digits, e.Period, e.Type)
}

// GoString cubre el formato %#v, que no usa String.
func (e Entry) GoString() string {
	return e.String()
}

// newID genera un UUID versión 4.
func newID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
