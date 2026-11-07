package totp

import (
	"testing"
	"time"
)

// Semillas públicas de RFC 6238, apéndice B. No son claves reales.
var (
	seedSHA1   = []byte("12345678901234567890")
	seedSHA256 = []byte("12345678901234567890123456789012")
	seedSHA512 = []byte("1234567890123456789012345678901234567890123456789012345678901234")
)

func TestCodeRFC6238(t *testing.T) {
	tests := []struct {
		unix                 int64
		sha1, sha256, sha512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	}

	for _, tt := range tests {
		for _, c := range []struct {
			algo string
			seed []byte
			want string
		}{
			{SHA1, seedSHA1, tt.sha1},
			{SHA256, seedSHA256, tt.sha256},
			{SHA512, seedSHA512, tt.sha512},
		} {
			got, err := Code(c.seed, time.Unix(tt.unix, 0), 30, 8, c.algo)
			if err != nil {
				t.Fatalf("Code(%s, %d): %v", c.algo, tt.unix, err)
			}
			if got != c.want {
				t.Errorf("Code(%s, %d) = %s, se esperaba %s", c.algo, tt.unix, got, c.want)
			}
		}
	}
}

// Vectores de RFC 4226, apéndice D. Con periodo 30, el contador n corresponde
// al instante n*30.
func TestCodeRFC4226(t *testing.T) {
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}

	for n, w := range want {
		got, err := Code(seedSHA1, time.Unix(int64(n)*30, 0), 30, 6, SHA1)
		if err != nil {
			t.Fatalf("contador %d: %v", n, err)
		}
		if got != w {
			t.Errorf("contador %d = %s, se esperaba %s", n, got, w)
		}
	}
}

func TestCodeKeepsLeadingZeros(t *testing.T) {
	got, err := Code(seedSHA1, time.Unix(1111111109, 0), 30, 6, SHA1)
	if err != nil {
		t.Fatal(err)
	}
	if got != "081804" {
		t.Errorf("código = %s, se esperaba 081804", got)
	}
}

func TestCodeUsesPeriod(t *testing.T) {
	// Con periodo 60, el instante 118 cae en el contador 1, igual que el 59 con periodo 30.
	got, err := Code(seedSHA1, time.Unix(118, 0), 60, 8, SHA1)
	if err != nil {
		t.Fatal(err)
	}
	if got != "94287082" {
		t.Errorf("código = %s, se esperaba 94287082", got)
	}
}

func TestCodeRejectsInvalidInput(t *testing.T) {
	now := time.Unix(59, 0)
	tests := []struct {
		name   string
		secret []byte
		t      time.Time
		period int
		digits int
		algo   string
	}{
		{"secreto nil", nil, now, 30, 6, SHA1},
		{"secreto vacío", []byte{}, now, 30, 6, SHA1},
		{"periodo cero", seedSHA1, now, 0, 6, SHA1},
		{"periodo negativo", seedSHA1, now, -30, 6, SHA1},
		{"cero dígitos", seedSHA1, now, 30, 0, SHA1},
		{"siete dígitos", seedSHA1, now, 30, 7, SHA1},
		{"algoritmo desconocido", seedSHA1, now, 30, 6, "MD5"},
		{"algoritmo vacío", seedSHA1, now, 30, 6, ""},
		{"tiempo anterior a 1970", seedSHA1, time.Unix(-1, 0), 30, 6, SHA1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := Code(tt.secret, tt.t, tt.period, tt.digits, tt.algo); err == nil {
				t.Errorf("no hubo error; código = %s", got)
			}
		})
	}
}

func TestRemaining(t *testing.T) {
	tests := []struct {
		unix   int64
		period int
		want   int
	}{
		{0, 30, 30},
		{1, 30, 29},
		{29, 30, 1},
		{30, 30, 30},
		{59, 30, 1},
		{59, 60, 1},
		{60, 60, 60},
	}

	for _, tt := range tests {
		got, err := Remaining(time.Unix(tt.unix, 0), tt.period)
		if err != nil {
			t.Fatalf("Remaining(%d, %d): %v", tt.unix, tt.period, err)
		}
		if got != tt.want {
			t.Errorf("Remaining(%d, %d) = %d, se esperaba %d", tt.unix, tt.period, got, tt.want)
		}
	}
}

func TestRemainingRejectsInvalidInput(t *testing.T) {
	if _, err := Remaining(time.Unix(59, 0), 0); err == nil {
		t.Error("periodo cero: no hubo error")
	}
	if _, err := Remaining(time.Unix(-1, 0), 30); err == nil {
		t.Error("tiempo anterior a 1970: no hubo error")
	}
}
