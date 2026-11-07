package cli

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"piko2fa/internal/tui"
	"piko2fa/internal/vault"
)

func TestTUIReleasesPasswordAndVaultLockWhileOpen(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.add("otpauth://totp/GitHub:ana?secret=" + rfcBase32)

	ran := false
	e.runTUI = func(m *tui.Model) error {
		ran = true
		for _, given := range e.console.given {
			if strings.Contains(string(given), testPassword) {
				t.Error("la contraseña sigue en memoria con la interfaz abierta")
			}
		}
		s, err := vault.Open(e.path)
		if err != nil {
			t.Errorf("el vault sigue bloqueado: %v", err)
			return nil
		}
		s.Close()
		if view := m.View(); !strings.Contains(view, "GitHub:ana") || !strings.Contains(view, "287 082") {
			t.Errorf("vista:\n%s", view)
		}
		return nil
	}
	e.mustRun([]string{testPassword}, nil, "tui")
	if !ran {
		t.Fatal("no se abrió la interfaz")
	}
}

func TestTUILockAsksPasswordAgainAndReloads(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.add("otpauth://totp/GitHub:ana?secret=" + rfcBase32)

	sessions := 0
	e.runTUI = func(m *tui.Model) error {
		sessions++
		if sessions == 1 {
			// Otro comando cambia el vault mientras la interfaz está abierta.
			s, err := vault.Open(e.path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := s.Load([]byte(testPassword)); err != nil {
				t.Fatal(err)
			}
			for _, entry := range s.List() {
				if err := s.Remove(entry.ID); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Save([]byte(testPassword)); err != nil {
				t.Fatal(err)
			}
			m.Update(tea.KeyMsg{Type: tea.KeyCtrlL})
			return nil
		}
		if view := m.View(); strings.Contains(view, "GitHub:ana") {
			t.Errorf("no recargó el vault:\n%s", view)
		}
		return nil
	}
	out := e.mustRun([]string{testPassword, testPassword}, nil, "tui")
	if sessions != 2 {
		t.Fatalf("sesiones = %d", sessions)
	}
	shouldContain(t, out, "Bloqueado")
}

func TestTUIClearsClipboardOnExit(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.add("otpauth://totp/GitHub:ana?secret=" + rfcBase32)
	e.now = e.now.Add(-20e9) // t = 39: quedan 21 s

	e.runTUI = func(m *tui.Model) error {
		m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		if e.clipboard.content != "287082" {
			t.Errorf("portapapeles = %q", e.clipboard.content)
		}
		m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
		return nil
	}
	e.mustRun([]string{testPassword}, nil, "tui")
	if e.clipboard.content != "" {
		t.Errorf("portapapeles al salir = %q", e.clipboard.content)
	}
}

func TestTUIClearsClipboardWhenInterfaceFails(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.add("otpauth://totp/GitHub:ana?secret=" + rfcBase32)
	e.now = e.now.Add(-20e9)

	failure := errors.New("fallo simulado")
	e.runTUI = func(m *tui.Model) error {
		m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		return failure
	}
	if _, err := e.run([]string{testPassword}, nil, "tui"); !errors.Is(err, failure) {
		t.Errorf("err = %v", err)
	}
	if e.clipboard.content != "" {
		t.Errorf("portapapeles = %q", e.clipboard.content)
	}
}

func TestTUIRefusesWithoutTerminalBeforeAskingPassword(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*env)
	}{
		{"stdin en tubería", func(e *env) { e.piped = true }},
		{"stdout redirigido", func(e *env) { e.noStdoutTerminal = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.init()
			tt.setup(e)
			e.runTUI = func(*tui.Model) error {
				t.Error("se abrió la interfaz")
				return nil
			}
			if _, err := e.run(nil, nil, "tui"); err == nil || !strings.Contains(err.Error(), "terminal") {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestTUIWrongPasswordDoesNotOpen(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.runTUI = func(*tui.Model) error {
		t.Error("se abrió la interfaz")
		return nil
	}
	if _, err := e.run([]string{otherPassword}, nil, "tui"); !errors.Is(err, vault.ErrInvalid) {
		t.Errorf("err = %v", err)
	}
}

func TestTUIRejectsArguments(t *testing.T) {
	e := newEnv(t)
	if _, err := e.run(nil, nil, "tui", "otpauth://totp/x?secret="+fakeBase32); err == nil {
		t.Fatal("no hubo error")
	} else if strings.Contains(err.Error(), fakeBase32) {
		t.Errorf("el error cita el argumento: %v", err)
	}
}
