package cli

import (
	"strings"
	"testing"
)

// Una URI pegada por error donde se espera una ruta no debe repetirse en los
// mensajes: los errores del sistema citan la ruta que recibieron.
func TestURIsPastedAsPathsAreNotRepeated(t *testing.T) {
	uri := "otpauth://totp/a?secret=" + fakeBase32

	tests := []struct {
		name    string
		secrets []string
		lines   []string
		args    []string
	}{
		{"import-ga --file", nil, nil, []string{"import-ga", "--file", uri}},
		{"restore", []string{testPassword}, nil, []string{"restore", uri}},
		{"export --encrypted", []string{testPassword}, nil, []string{"export", "--encrypted", uri}},
		{"export --plaintext", []string{testPassword}, []string{"EXPORTAR"}, []string{"export", "--plaintext", uri}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.init()
			out, err := e.run(tt.secrets, tt.lines, tt.args...)
			if err == nil {
				t.Fatalf("no hubo error: %s", out)
			}
			text := out + err.Error() + strings.Join(e.console.prompts, " ")
			if strings.Contains(text, fakeBase32) {
				t.Errorf("repite la clave: %s", text)
			}
		})
	}
}

func TestSingularAndPluralMessages(t *testing.T) {
	e := newEnv(t)
	e.init()
	shouldContain(t, e.list(), "0 cuentas")
	e.add(totpURI("A", "a", rfcBase32))

	out := e.list()
	shouldContain(t, out, "1 cuenta\n")
	e.add(totpURI("B", "b", fakeBase32))
	shouldContain(t, e.list(), "2 cuentas\n")
}

func TestUnknownCommandMessage(t *testing.T) {
	e := newEnv(t)
	_, err := e.run(nil, nil, "lits")
	if err == nil || !strings.Contains(err.Error(), "comando desconocido") {
		t.Errorf("err = %v", err)
	}
}

func TestWrongArgumentCountMessage(t *testing.T) {
	e := newEnv(t)
	for _, args := range [][]string{{"rm"}, {"rm", "a", "b"}, {"restore"}, {"list", "a", "b"}} {
		_, err := e.run(nil, nil, args...)
		if err == nil || !strings.Contains(err.Error(), "número de argumentos") {
			t.Errorf("%v: err = %v", args, err)
		}
	}
}
