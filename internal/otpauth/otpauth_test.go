package otpauth

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"piko2fa/internal/model"
	"piko2fa/internal/totp"
)

// Clave falsa de ejemplo y sus bytes.
const fakeBase32 = "JBSWY3DPEHPK3PXP"

var fakeSecret = []byte("Hello!\xde\xad\xbe\xef")

func TestParse(t *testing.T) {
	tests := []struct {
		name, uri     string
		wantName      string
		wantIssuer    string
		wantAlgorithm string
		wantDigits    int
		wantPeriod    int
	}{
		{
			name:     "todos los parámetros",
			uri:      "otpauth://totp/GitHub:usuario@example.com?secret=" + fakeBase32 + "&issuer=GitHub&algorithm=SHA256&digits=8&period=60",
			wantName: "usuario@example.com", wantIssuer: "GitHub", wantAlgorithm: totp.SHA256, wantDigits: 8, wantPeriod: 60,
		},
		{
			name:     "valores por defecto",
			uri:      "otpauth://totp/usuario?secret=" + fakeBase32,
			wantName: "usuario", wantIssuer: "", wantAlgorithm: totp.SHA1, wantDigits: 6, wantPeriod: 30,
		},
		{
			name:     "emisor solo en la etiqueta",
			uri:      "otpauth://totp/GitHub:usuario?secret=" + fakeBase32,
			wantName: "usuario", wantIssuer: "GitHub", wantAlgorithm: totp.SHA1, wantDigits: 6, wantPeriod: 30,
		},
		{
			name:     "emisor solo en el parámetro",
			uri:      "otpauth://totp/usuario?secret=" + fakeBase32 + "&issuer=GitHub",
			wantName: "usuario", wantIssuer: "GitHub", wantAlgorithm: totp.SHA1, wantDigits: 6, wantPeriod: 30,
		},
		{
			name:     "emisor distinto: gana el parámetro",
			uri:      "otpauth://totp/Viejo:usuario?secret=" + fakeBase32 + "&issuer=Nuevo",
			wantName: "usuario", wantIssuer: "Nuevo", wantAlgorithm: totp.SHA1, wantDigits: 6, wantPeriod: 30,
		},
		{
			name:     "etiqueta codificada",
			uri:      "otpauth://totp/Mi%20Empresa%3Ausuario%40example.com?secret=" + fakeBase32 + "&issuer=Mi%20Empresa",
			wantName: "usuario@example.com", wantIssuer: "Mi Empresa", wantAlgorithm: totp.SHA1, wantDigits: 6, wantPeriod: 30,
		},
		{
			name:     "espacio tras los dos puntos",
			uri:      "otpauth://totp/GitHub:%20usuario?secret=" + fakeBase32,
			wantName: "usuario", wantIssuer: "GitHub", wantAlgorithm: totp.SHA1, wantDigits: 6, wantPeriod: 30,
		},
		{
			name:     "espacio codificado como + en el emisor",
			uri:      "otpauth://totp/usuario?secret=" + fakeBase32 + "&issuer=Mi+Empresa",
			wantName: "usuario", wantIssuer: "Mi Empresa", wantAlgorithm: totp.SHA1, wantDigits: 6, wantPeriod: 30,
		},
		{
			name:     "algoritmo en minúsculas y parámetros desconocidos",
			uri:      "otpauth://totp/usuario?secret=" + fakeBase32 + "&algorithm=sha512&image=https%3A%2F%2Fexample.com%2Fa.png",
			wantName: "usuario", wantIssuer: "", wantAlgorithm: totp.SHA512, wantDigits: 6, wantPeriod: 30,
		},
		{
			name:     "esquema y tipo en mayúsculas, con espacios alrededor",
			uri:      "  OTPAUTH://TOTP/usuario?secret=" + fakeBase32 + "\n",
			wantName: "usuario", wantIssuer: "", wantAlgorithm: totp.SHA1, wantDigits: 6, wantPeriod: 30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := Parse(tt.uri)
			if err != nil {
				t.Fatal(err)
			}
			if e.Name != tt.wantName {
				t.Errorf("Name = %q, se esperaba %q", e.Name, tt.wantName)
			}
			if e.Issuer != tt.wantIssuer {
				t.Errorf("Issuer = %q, se esperaba %q", e.Issuer, tt.wantIssuer)
			}
			if e.Algorithm != tt.wantAlgorithm {
				t.Errorf("Algorithm = %q, se esperaba %q", e.Algorithm, tt.wantAlgorithm)
			}
			if e.Digits != tt.wantDigits {
				t.Errorf("Digits = %d, se esperaba %d", e.Digits, tt.wantDigits)
			}
			if e.Period != tt.wantPeriod {
				t.Errorf("Period = %d, se esperaba %d", e.Period, tt.wantPeriod)
			}
			if !bytes.Equal(e.Secret, fakeSecret) {
				t.Error("secreto incorrecto")
			}
			if e.ID == "" || e.CreatedAt.IsZero() {
				t.Error("faltan ID o CreatedAt")
			}
		})
	}
}

func TestParseRejectsInvalidURIs(t *testing.T) {
	tests := []struct{ name, uri string }{
		{"vacía", ""},
		{"otro esquema", "https://totp/usuario?secret=" + fakeBase32},
		{"tipo desconocido", "otpauth://otro/usuario?secret=" + fakeBase32},
		{"sin secreto", "otpauth://totp/usuario?issuer=GitHub"},
		{"secreto vacío", "otpauth://totp/usuario?secret="},
		{"secreto no base32", "otpauth://totp/usuario?secret=JBSW!Y3DP"},
		{"secreto con relleno interior", "otpauth://totp/usuario?secret=JBSW=Y3DP"},
		{"secreto de longitud imposible", "otpauth://totp/usuario?secret=JBSWY3D2A"},
		{"secreto repetido", "otpauth://totp/usuario?secret=" + fakeBase32 + "&secret=GEZDGNBV"},
		{"sin nombre ni emisor", "otpauth://totp/?secret=" + fakeBase32},
		{"algoritmo MD5", "otpauth://totp/usuario?secret=" + fakeBase32 + "&algorithm=MD5"},
		{"siete dígitos", "otpauth://totp/usuario?secret=" + fakeBase32 + "&digits=7"},
		{"dígitos no numéricos", "otpauth://totp/usuario?secret=" + fakeBase32 + "&digits=seis"},
		{"dígitos vacíos", "otpauth://totp/usuario?secret=" + fakeBase32 + "&digits="},
		{"periodo cero", "otpauth://totp/usuario?secret=" + fakeBase32 + "&period=0"},
		{"periodo negativo", "otpauth://totp/usuario?secret=" + fakeBase32 + "&period=-30"},
		{"escape incorrecto en la etiqueta", "otpauth://totp/a%zz?secret=" + fakeBase32},
		{"escape incorrecto en la consulta", "otpauth://totp/usuario?secret=" + fakeBase32 + "&issuer=%zz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if e, err := Parse(tt.uri); err == nil {
				t.Errorf("no hubo error: %v", e)
			}
		})
	}
}

func TestParseRejectsHOTP(t *testing.T) {
	_, err := Parse("otpauth://hotp/usuario?secret=" + fakeBase32 + "&counter=1")
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("err = %v, se esperaba ErrUnsupportedType", err)
	}
}

func TestErrorsDoNotLeakSecret(t *testing.T) {
	tests := []struct{ name, uri string }{
		{"escape incorrecto en la etiqueta", "otpauth://totp/a%zz?secret=" + fakeBase32},
		{"carácter de control", "otpauth://totp/a\x7f?secret=" + fakeBase32},
		{"esquema no válido", "1otpauth://totp/a?secret=" + fakeBase32},
		{"host no válido", "otpauth://to tp/a?secret=" + fakeBase32},
		{"otro tipo", "otpauth://otro/a?secret=" + fakeBase32},
		{"escape incorrecto en la consulta", "otpauth://totp/a?secret=" + fakeBase32 + "&x=%zz"},
		{"parámetro malformado junto al secreto", "otpauth://totp/a?secret=" + fakeBase32 + ";x=1"},
		{"secreto no base32", "otpauth://totp/a?secret=" + fakeBase32 + "!"},
		{"dígitos con el secreto", "otpauth://totp/a?secret=GEZDGNBV&digits=" + fakeBase32},
		{"algoritmo con el secreto", "otpauth://totp/a?secret=GEZDGNBV&algorithm=" + fakeBase32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.uri)
			if err == nil {
				t.Fatal("no hubo error")
			}
			if strings.Contains(strings.ToUpper(err.Error()), fakeBase32) {
				t.Errorf("el error muestra el secreto: %v", err)
			}
		})
	}
}

func TestDecodeSecretIsTolerant(t *testing.T) {
	for _, s := range []string{
		"JBSWY3DPEHPK3PXP",
		"jbswy3dpehpk3pxp",
		"JbSwY3dPeHpK3pXp",
		"JBSW Y3DP EHPK 3PXP",
		" JBSWY3DPEHPK3PXP\t\n",
	} {
		got, err := DecodeSecret(s)
		if err != nil {
			t.Errorf("DecodeSecret(%q): %v", s, err)
			continue
		}
		if !bytes.Equal(got, fakeSecret) {
			t.Errorf("DecodeSecret(%q): bytes incorrectos", s)
		}
	}
}

func TestDecodeSecretPadding(t *testing.T) {
	want := []byte("Hello")
	for _, s := range []string{"JBSWY3DP", "JBSWY3DP========"} {
		got, err := DecodeSecret(s)
		if err != nil {
			t.Errorf("DecodeSecret(%q): %v", s, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("DecodeSecret(%q): bytes incorrectos", s)
		}
	}

	// Secreto cuya longitud sí necesita relleno en base32 estándar.
	for _, s := range []string{"MFRA", "MFRA====", "mfra"} {
		got, err := DecodeSecret(s)
		if err != nil {
			t.Errorf("DecodeSecret(%q): %v", s, err)
			continue
		}
		if !bytes.Equal(got, []byte("ab")) {
			t.Errorf("DecodeSecret(%q): bytes incorrectos", s)
		}
	}
}

func TestEncodeSecretHasNoPadding(t *testing.T) {
	if got := EncodeSecret([]byte("ab")); got != "MFRA" {
		t.Errorf("EncodeSecret = %q, se esperaba MFRA", got)
	}
}

func TestFormatRoundTrip(t *testing.T) {
	tests := []struct {
		name, account, issuer, algorithm string
		digits, period                   int
	}{
		{"completa", "usuario@example.com", "GitHub", totp.SHA1, 6, 30},
		{"otros parámetros", "usuario", "GitHub", totp.SHA512, 8, 60},
		{"sin emisor", "usuario", "", totp.SHA256, 6, 30},
		{"sin nombre", "", "GitHub", totp.SHA1, 6, 30},
		{"espacios", "mi usuario", "Mi Empresa", totp.SHA1, 6, 30},
		{"signo más", "a+b@example.com", "C+D", totp.SHA1, 6, 30},
		{"caracteres especiales", "año/ñu?#&%", "Café & Té", totp.SHA1, 6, 30},
		{"dos puntos en el emisor", "usuario", "A:B", totp.SHA1, 6, 30},
		{"dos puntos en el nombre", "a:b", "Emisor", totp.SHA1, 6, 30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, err := model.New(tt.account, tt.issuer, fakeSecret, tt.algorithm, tt.digits, tt.period)
			if err != nil {
				t.Fatal(err)
			}
			uri, err := Format(want)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Parse(uri)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got.Name != want.Name || got.Issuer != want.Issuer || got.Algorithm != want.Algorithm ||
				got.Digits != want.Digits || got.Period != want.Period || !bytes.Equal(got.Secret, want.Secret) {
				t.Errorf("la cuenta cambió: %v, se esperaba %v", got, want)
			}
		})
	}
}

func TestFormatOutput(t *testing.T) {
	e, err := model.New("mi usuario", "Mi Empresa", fakeSecret, totp.SHA1, 6, 30)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Format(e)
	if err != nil {
		t.Fatal(err)
	}
	want := "otpauth://totp/Mi%20Empresa:mi%20usuario?algorithm=SHA1&digits=6&issuer=Mi%20Empresa&period=30&secret=" + fakeBase32
	if got != want {
		t.Errorf("Format = %s\nse esperaba  %s", got, want)
	}
}

func TestFormatRejectsInvalidEntry(t *testing.T) {
	if _, err := Format(model.Entry{Name: "a"}); err == nil {
		t.Error("no hubo error")
	}
}

// De la URI al código: semilla pública de RFC 6238 codificada en base32.
func TestParsedEntryGeneratesRFCCode(t *testing.T) {
	e, err := Parse("otpauth://totp/rfc?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8")
	if err != nil {
		t.Fatal(err)
	}
	got, err := totp.Code(e.Secret, time.Unix(59, 0), e.Period, e.Digits, e.Algorithm)
	if err != nil {
		t.Fatal(err)
	}
	if got != "94287082" {
		t.Errorf("código = %s, se esperaba 94287082", got)
	}
}
