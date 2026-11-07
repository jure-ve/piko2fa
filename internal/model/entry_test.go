package model

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"piko2fa/internal/totp"
)

var fakeSecret = []byte("Hello!\xde\xad\xbe\xef")

func TestNew(t *testing.T) {
	e, err := New("usuario@example.com", "GitHub", fakeSecret, totp.SHA256, 8, 60)
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "usuario@example.com" || e.Issuer != "GitHub" || e.Algorithm != totp.SHA256 ||
		e.Digits != 8 || e.Period != 60 || e.Type != TypeTOTP {
		t.Errorf("campos incorrectos: %v", e)
	}
	if e.CreatedAt.IsZero() {
		t.Error("CreatedAt vacío")
	}
}

func TestNewIDIsUniqueUUIDv4(t *testing.T) {
	uuidV4 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for range 100 {
		id := newID()
		if !uuidV4.MatchString(id) {
			t.Fatalf("no es un UUID v4: %s", id)
		}
		if seen[id] {
			t.Fatalf("ID repetido: %s", id)
		}
		seen[id] = true
	}
}

func TestNewRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name           string
		account        string
		issuer         string
		secret         []byte
		algorithm      string
		digits, period int
	}{
		{"sin nombre ni emisor", "", "", fakeSecret, totp.SHA1, 6, 30},
		{"secreto nil", "a", "b", nil, totp.SHA1, 6, 30},
		{"secreto vacío", "a", "b", []byte{}, totp.SHA1, 6, 30},
		{"algoritmo desconocido", "a", "b", fakeSecret, "MD5", 6, 30},
		{"siete dígitos", "a", "b", fakeSecret, totp.SHA1, 7, 30},
		{"periodo cero", "a", "b", fakeSecret, totp.SHA1, 6, 0},
		{"periodo negativo", "a", "b", fakeSecret, totp.SHA1, 6, -30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.account, tt.issuer, tt.secret, tt.algorithm, tt.digits, tt.period); err == nil {
				t.Error("no hubo error")
			}
		})
	}
}

func TestNewAcceptsOnlyNameOrOnlyIssuer(t *testing.T) {
	if _, err := New("cuenta", "", fakeSecret, totp.SHA1, 6, 30); err != nil {
		t.Errorf("solo nombre: %v", err)
	}
	if _, err := New("", "emisor", fakeSecret, totp.SHA1, 6, 30); err != nil {
		t.Errorf("solo emisor: %v", err)
	}
}

func TestValidateRejectsOtherTypes(t *testing.T) {
	e, err := New("a", "b", fakeSecret, totp.SHA1, 6, 30)
	if err != nil {
		t.Fatal(err)
	}
	e.Type = "hotp"
	if err := e.Validate(); err == nil {
		t.Error("no hubo error")
	}
}

func TestPrintingOmitsSecret(t *testing.T) {
	e, err := New("a", "b", fakeSecret, totp.SHA1, 6, 30)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(format, e)
		if strings.Contains(out, "Hello") || strings.Contains(out, "72 101") {
			t.Errorf("%s muestra el secreto: %s", format, out)
		}
	}
}
