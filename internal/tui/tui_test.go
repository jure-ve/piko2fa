package tui

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"piko2fa/internal/model"
)

// Semilla falsa de RFC 4226: el contador 1 da 287082 y el contador 2, 359152.
var rfcSecret = []byte("12345678901234567890")

const (
	codeCounter1 = "287082"
	codeCounter2 = "359152"
)

type fakeClipboard struct {
	content  string
	failRead bool
}

func (c *fakeClipboard) ReadAll() (string, error) {
	if c.failRead {
		return "", errors.New("fallo simulado")
	}
	return c.content, nil
}

func (c *fakeClipboard) WriteAll(text string) error {
	c.content = text
	return nil
}

type harness struct {
	t         *testing.T
	m         *Model
	clipboard *fakeClipboard
	now       time.Time
}

func newEntry(t *testing.T, name, issuer string) model.Entry {
	t.Helper()
	e, err := model.New(name, issuer, bytes.Clone(rfcSecret), model.DefaultAlgorithm, model.DefaultDigits, model.DefaultPeriod)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func newHarness(t *testing.T, labels ...string) *harness {
	t.Helper()
	h := &harness{t: t, clipboard: &fakeClipboard{}, now: time.Unix(31, 0)}
	entries := make([]model.Entry, 0, len(labels))
	for _, l := range labels {
		issuer, name, _ := strings.Cut(l, ":")
		entries = append(entries, newEntry(t, name, issuer))
	}
	h.m = New(entries, h.clipboard, func() time.Time { return h.now })
	return h
}

func (h *harness) key(msg tea.KeyMsg) tea.Cmd {
	h.t.Helper()
	_, cmd := h.m.Update(msg)
	return cmd
}

func (h *harness) press(t tea.KeyType) tea.Cmd {
	h.t.Helper()
	return h.key(tea.KeyMsg{Type: t})
}

func (h *harness) typeText(text string) {
	h.t.Helper()
	for _, r := range text {
		h.key(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}

// advance mueve el reloj y entrega un tick.
func (h *harness) advance(d time.Duration) tea.Cmd {
	h.t.Helper()
	h.now = h.now.Add(d)
	_, cmd := h.m.Update(tickMsg{})
	return cmd
}

func isQuit(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	_, ok := cmd().(tea.QuitMsg)
	return ok
}

func TestFilterMatchesAllWordsIgnoringCase(t *testing.T) {
	h := newHarness(t, "GitHub:ana", "GitHub:beto", "Google:ana")
	tests := []struct {
		filter string
		want   int
	}{
		{"", 3},
		{"GITHUB", 2},
		{"ana", 2},
		{"github ana", 1},
		{"ana github", 1},
		{"nada", 0},
	}
	for _, tt := range tests {
		h.press(tea.KeyCtrlU)
		h.typeText(tt.filter)
		if got := len(h.m.visible); got != tt.want {
			t.Errorf("filtro %q: %d cuentas, se esperaban %d", tt.filter, got, tt.want)
		}
	}
}

func TestBackspaceWidensFilterAndResetsCursor(t *testing.T) {
	h := newHarness(t, "a:1", "a:2", "b:3")
	h.press(tea.KeyDown)
	h.press(tea.KeyDown)
	h.typeText("b")
	if h.m.cursor != 0 || len(h.m.visible) != 1 {
		t.Fatalf("cursor = %d, visibles = %d", h.m.cursor, len(h.m.visible))
	}
	h.press(tea.KeyBackspace)
	if len(h.m.visible) != 3 {
		t.Errorf("visibles = %d", len(h.m.visible))
	}
	h.press(tea.KeyBackspace) // sin nada que borrar
}

func TestPastedTextIsNotShown(t *testing.T) {
	h := newHarness(t, "a:1")
	h.key(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"), Paste: true})
	if strings.Contains(h.m.View(), "JBSWY3DPEHPK3PXP") {
		t.Error("lo pegado aparece en pantalla")
	}
}

func TestNavigationStaysInBoundsAndScrolls(t *testing.T) {
	labels := make([]string, 50)
	for i := range labels {
		labels[i] = fmt.Sprintf("Emisor:cuenta%02d", i)
	}
	h := newHarness(t, labels...)
	h.m.Update(tea.WindowSizeMsg{Width: 80, Height: 16})

	h.press(tea.KeyUp)
	if h.m.cursor != 0 {
		t.Errorf("cursor = %d al subir desde el principio", h.m.cursor)
	}
	h.press(tea.KeyPgDown)
	if h.m.cursor != 10 || h.m.offset != 1 {
		t.Errorf("tras avanzar una página: cursor = %d, offset = %d", h.m.cursor, h.m.offset)
	}
	if view := h.m.View(); !strings.Contains(view, "cuenta10") || strings.Contains(view, "cuenta00") {
		t.Errorf("la vista no siguió al cursor:\n%s", view)
	}
	h.press(tea.KeyEnd)
	if h.m.cursor != 49 {
		t.Errorf("cursor = %d al final", h.m.cursor)
	}
	h.press(tea.KeyDown)
	if h.m.cursor != 49 {
		t.Errorf("cursor = %d tras pasar del final", h.m.cursor)
	}
	h.press(tea.KeyHome)
	if h.m.cursor != 0 || h.m.offset != 0 {
		t.Errorf("al inicio: cursor = %d, offset = %d", h.m.cursor, h.m.offset)
	}

	h.press(tea.KeyEnd)
	h.m.Update(tea.WindowSizeMsg{Width: 80, Height: 3}) // ventana diminuta
	if view := h.m.View(); !strings.Contains(view, "cuenta49") {
		t.Errorf("la fila seleccionada no se ve:\n%s", view)
	}
}

func TestEmptyStates(t *testing.T) {
	h := newHarness(t)
	h.press(tea.KeyEnter)
	h.press(tea.KeyDown)
	h.advance(time.Second)
	if view := h.m.View(); !strings.Contains(view, "No hay cuentas") {
		t.Errorf("vault vacío:\n%s", view)
	}

	h = newHarness(t, "a:1")
	h.typeText("zzz")
	h.press(tea.KeyEnter)
	if h.clipboard.content != "" {
		t.Errorf("copió sin selección: %q", h.clipboard.content)
	}
	if view := h.m.View(); !strings.Contains(view, "Ninguna cuenta") {
		t.Errorf("sin coincidencias:\n%s", view)
	}
}

func TestViewShowsLiveCodesButNeverSecrets(t *testing.T) {
	h := newHarness(t, "GitHub:ana")
	if view := h.m.View(); !strings.Contains(view, "287 082") {
		t.Errorf("no aparece el código:\n%s", view)
	}
	h.advance(29 * time.Second)
	view := h.m.View()
	if !strings.Contains(view, "359 152") {
		t.Errorf("el código no cambió con el periodo:\n%s", view)
	}
	for _, secret := range []string{string(rfcSecret), "GEZDGNBVGY3TQOJQ"} {
		if strings.Contains(view, secret) {
			t.Errorf("la vista contiene el secreto:\n%s", view)
		}
	}
}

func TestSanitizeRemovesTerminalControls(t *testing.T) {
	h := newHarness(t, "Evil\x1b]0;titulo\x07:ana\x1b[2J\n\u202e")
	view := h.m.View()
	for _, bad := range []string{"\x1b]", "\x07", "\x1b[2J", "\u202e"} {
		if strings.Contains(view, bad) {
			t.Errorf("la vista contiene %q", bad)
		}
	}
	if !strings.Contains(view, "Evil]0;titulo:ana[2J") {
		t.Errorf("el nombre se perdió:\n%q", view)
	}
}

func TestCopyWritesPlainCodeAndClearsAtExpiry(t *testing.T) {
	h := newHarness(t, "GitHub:ana")
	h.press(tea.KeyEnter)
	if h.clipboard.content != codeCounter1 {
		t.Fatalf("portapapeles = %q", h.clipboard.content)
	}
	if strings.Contains(h.m.status, codeCounter1) {
		t.Errorf("el mensaje repite el código: %q", h.m.status)
	}

	h.advance(28 * time.Second)
	if h.clipboard.content != codeCounter1 {
		t.Error("limpió antes de expirar")
	}
	h.advance(time.Second) // t = 60
	if h.clipboard.content != "" {
		t.Errorf("no limpió al expirar: %q", h.clipboard.content)
	}
	if !strings.Contains(h.m.status, "limpio") {
		t.Errorf("status = %q", h.m.status)
	}
}

func TestCopyKeepsWhatUserCopiedLater(t *testing.T) {
	h := newHarness(t, "GitHub:ana")
	h.press(tea.KeyEnter)
	h.clipboard.content = "algo que copió el usuario"
	h.advance(29 * time.Second)
	if h.clipboard.content != "algo que copió el usuario" {
		t.Errorf("portapapeles = %q", h.clipboard.content)
	}
	if strings.Contains(h.m.status, "limpio") {
		t.Errorf("dijo que limpió sin hacerlo: %q", h.m.status)
	}
}

func TestCopyNearExpiryWaitsForNextCode(t *testing.T) {
	h := newHarness(t, "GitHub:ana")
	h.now = time.Unix(56, 0) // quedan 4 s
	h.press(tea.KeyEnter)
	if h.clipboard.content != "" {
		t.Fatalf("copió un código a punto de expirar: %q", h.clipboard.content)
	}
	if !strings.Contains(h.m.status, "Esperando") {
		t.Errorf("status = %q", h.m.status)
	}
	h.advance(3 * time.Second)
	if h.clipboard.content != "" {
		t.Fatal("copió antes del cambio de código")
	}
	h.advance(time.Second) // t = 60
	if h.clipboard.content != codeCounter2 {
		t.Fatalf("portapapeles = %q", h.clipboard.content)
	}
	h.advance(29 * time.Second)
	if h.clipboard.content != codeCounter2 {
		t.Error("el código nuevo se limpió antes de expirar")
	}
}

func TestEscCancelsPendingCopyThenFilterThenQuits(t *testing.T) {
	h := newHarness(t, "GitHub:ana")
	h.now = time.Unix(56, 0)
	h.typeText("git")
	h.press(tea.KeyEnter)

	if cmd := h.press(tea.KeyEsc); isQuit(cmd) || h.m.pending != noneSelected {
		t.Fatal("Esc no canceló la copia pendiente")
	}
	h.advance(4 * time.Second)
	if h.clipboard.content != "" {
		t.Errorf("copió tras cancelar: %q", h.clipboard.content)
	}
	if cmd := h.press(tea.KeyEsc); isQuit(cmd) || len(h.m.filter) != 0 {
		t.Fatal("Esc no limpió el filtro")
	}
	if cmd := h.press(tea.KeyEsc); !isQuit(cmd) {
		t.Fatal("Esc no salió")
	}
	if h.m.Locked() {
		t.Error("salir no es bloquear")
	}
}

func TestLockAfterIdle(t *testing.T) {
	h := newHarness(t, "GitHub:ana")
	if cmd := h.advance(IdleTimeout - time.Second); isQuit(cmd) || h.m.Locked() {
		t.Fatal("se bloqueó antes de tiempo")
	}
	h.typeText("g") // una tecla reinicia la cuenta
	if cmd := h.advance(IdleTimeout - time.Second); isQuit(cmd) || h.m.Locked() {
		t.Fatal("la tecla no reinició la cuenta")
	}
	if cmd := h.advance(time.Second); !isQuit(cmd) || !h.m.Locked() {
		t.Fatal("no se bloqueó")
	}
}

func TestKeyAfterSuspendLocksInsteadOfActing(t *testing.T) {
	h := newHarness(t, "GitHub:ana")
	h.now = h.now.Add(time.Hour)
	cmd := h.press(tea.KeyEnter)
	if !isQuit(cmd) || !h.m.Locked() {
		t.Fatal("no se bloqueó al despertar")
	}
	if h.clipboard.content != "" {
		t.Errorf("copió tras la suspensión: %q", h.clipboard.content)
	}
}

func TestIdleUsesWallClock(t *testing.T) {
	// Un reloj con lectura monotónica casi detenida, como tras una suspensión.
	start := time.Now()
	current := start
	m := New(nil, &fakeClipboard{}, func() time.Time { return current })
	current = start.Round(0).Add(time.Hour)
	if !m.idleExpired() {
		t.Error("no contó el tiempo suspendido")
	}
}

func TestManualLockAndQuit(t *testing.T) {
	h := newHarness(t, "GitHub:ana")
	if cmd := h.press(tea.KeyCtrlL); !isQuit(cmd) || !h.m.Locked() {
		t.Error("Ctrl+L no bloqueó")
	}
	h = newHarness(t, "GitHub:ana")
	if cmd := h.press(tea.KeyCtrlC); !isQuit(cmd) || h.m.Locked() {
		t.Error("Ctrl+C debe salir sin bloquear")
	}
}

func TestCloseZeroesSecretsAndClearsClipboard(t *testing.T) {
	h := newHarness(t, "GitHub:ana", "Google:beto")
	secrets := [][]byte{h.m.entries[0].Secret, h.m.entries[1].Secret}
	h.press(tea.KeyEnter)

	if err := h.m.Close(); err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Error("el secreto no quedó a cero")
		}
	}
	if h.clipboard.content != "" {
		t.Errorf("portapapeles = %q", h.clipboard.content)
	}
	if err := h.m.Close(); err != nil {
		t.Errorf("segundo Close: %v", err)
	}
	h.m.View() // no debe fallar tras cerrar
}

func TestCloseKeepsWhatUserCopied(t *testing.T) {
	h := newHarness(t, "GitHub:ana")
	h.press(tea.KeyEnter)
	h.clipboard.content = "otra cosa"
	if err := h.m.Close(); err != nil {
		t.Fatal(err)
	}
	if h.clipboard.content != "otra cosa" {
		t.Errorf("portapapeles = %q", h.clipboard.content)
	}
}

func TestCloseReportsClipboardFailure(t *testing.T) {
	h := newHarness(t, "GitHub:ana")
	h.press(tea.KeyEnter)
	h.clipboard.failRead = true
	err := h.m.Close()
	if err == nil {
		t.Fatal("no hubo error")
	}
	if strings.Contains(err.Error(), codeCounter1) {
		t.Errorf("el error cita el código: %v", err)
	}
}
