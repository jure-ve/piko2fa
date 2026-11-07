// Package tui implementa la interfaz interactiva: una lista filtrable con códigos
// en vivo. Es de solo lectura: trabaja con una copia de las cuentas en memoria y
// nunca recibe la contraseña ni escribe en el vault.
package tui

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"

	"piko2fa/internal/model"
	"piko2fa/internal/totp"
)

const (
	// IdleTimeout es el tiempo sin pulsar teclas tras el que se bloquea.
	IdleTimeout = 5 * time.Minute

	// nearExpiry son los segundos restantes con los que un código ya no da tiempo
	// a pegarlo: se espera al siguiente.
	nearExpiry = 5

	// chromeLines son las líneas que no son filas de cuentas.
	chromeLines   = 6
	defaultHeight = 24

	noneSelected = -1

	styleReverse    = "\x1b[7m"
	styleReverseOff = "\x1b[27m"
	styleWarn       = "\x1b[33m"
	styleWarnOff    = "\x1b[39m"
)

// Clipboard accede al portapapeles del sistema.
type Clipboard interface {
	ReadAll() (string, error)
	WriteAll(text string) error
}

type tickMsg struct{}

// Model es el estado de la interfaz. Toma posesión de las cuentas que recibe:
// Close pone a cero sus secretos.
type Model struct {
	entries   []model.Entry
	labels    []string
	now       func() time.Time
	clipboard Clipboard

	filter  []rune
	visible []int
	cursor  int
	offset  int
	height  int

	lastKey time.Time
	locked  bool
	status  string

	pending int // cuenta que se copiará al cambiar el código
	copied  string
	clearAt time.Time
}

var _ tea.Model = (*Model)(nil)

// New prepara la interfaz con las cuentas en el orden en que se mostrarán.
func New(entries []model.Entry, clipboard Clipboard, now func() time.Time) *Model {
	m := &Model{
		entries:   entries,
		labels:    make([]string, len(entries)),
		now:       now,
		clipboard: clipboard,
		pending:   noneSelected,
	}
	for i, e := range entries {
		m.labels[i] = sanitize(e.Label())
	}
	m.lastKey = m.clock()
	m.applyFilter()
	return m
}

// sanitize quita los caracteres de control: el nombre de una cuenta viene de un
// QR, y una secuencia de escape podría alterar lo que muestra la terminal.
func sanitize(text string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, text)
}

// clock quita la lectura monotónica, que puede detenerse con el equipo suspendido:
// al despertar, el tiempo sin uso debe incluir la suspensión.
func (m *Model) clock() time.Time {
	return m.now().Round(0)
}

// Locked indica si la interfaz terminó por un bloqueo y no porque el usuario
// quisiera salir.
func (m *Model) Locked() bool {
	return m.locked
}

// Close pone a cero los secretos y quita del portapapeles el código copiado, salvo
// que el usuario haya copiado otra cosa después.
func (m *Model) Close() error {
	for _, e := range m.entries {
		clear(e.Secret)
	}
	m.entries, m.labels, m.visible = nil, nil, nil
	m.pending = noneSelected
	_, err := m.clearCopied()
	return err
}

// clearCopied indica si llegó a borrar el código: no lo hace si el usuario copió
// otra cosa después.
func (m *Model) clearCopied() (bool, error) {
	if m.copied == "" {
		return false, nil
	}
	copied := m.copied
	m.copied = ""
	current, err := m.clipboard.ReadAll()
	if err != nil {
		return false, errors.New("no se pudo limpiar el portapapeles")
	}
	if current != copied {
		return false, nil
	}
	if err := m.clipboard.WriteAll(""); err != nil {
		return false, errors.New("no se pudo limpiar el portapapeles")
	}
	return true, nil
}

func tick() tea.Cmd {
	return tea.Every(time.Second, func(time.Time) tea.Msg { return tickMsg{} })
}

// Init arranca el reloj.
func (m *Model) Init() tea.Cmd {
	return tick()
}

// Update atiende las teclas, el reloj y los cambios de tamaño.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.height = msg.Height
		m.keepCursorVisible()
	case tickMsg:
		if m.idleExpired() {
			return m.lock()
		}
		m.onTick()
		return m, tick()
	case tea.KeyMsg:
		// Una tecla al despertar del equipo no debe evitar el bloqueo.
		if m.idleExpired() {
			return m.lock()
		}
		m.lastKey = m.clock()
		return m.onKey(msg)
	}
	return m, nil
}

func (m *Model) idleExpired() bool {
	return m.clock().Sub(m.lastKey) >= IdleTimeout
}

func (m *Model) lock() (tea.Model, tea.Cmd) {
	m.locked = true
	return m, tea.Quit
}

func (m *Model) onTick() {
	now := m.clock()
	if m.copied != "" && !now.Before(m.clearAt) {
		switch cleared, err := m.clearCopied(); {
		case err != nil:
			m.status = err.Error()
		case cleared:
			m.status = "Portapapeles limpio. El historial del portapapeles (Win+V) puede conservar el código."
		default:
			m.status = ""
		}
	}
	if m.pending != noneSelected && !m.mustWait(m.entries[m.pending], now) {
		i := m.pending
		m.pending = noneSelected
		m.copyNow(i, now)
	}
}

func (m *Model) onKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyCtrlL:
		return m.lock()
	case tea.KeyEsc:
		switch {
		case m.pending != noneSelected:
			m.pending = noneSelected
			m.status = "Copia cancelada."
		case len(m.filter) > 0:
			m.filter = nil
			m.applyFilter()
		default:
			return m, tea.Quit
		}
	case tea.KeyEnter:
		m.copySelected()
	case tea.KeyUp:
		m.moveCursor(-1)
	case tea.KeyDown:
		m.moveCursor(1)
	case tea.KeyPgUp:
		m.moveCursor(-m.pageSize())
	case tea.KeyPgDown:
		m.moveCursor(m.pageSize())
	case tea.KeyHome:
		m.moveCursor(-len(m.visible))
	case tea.KeyEnd:
		m.moveCursor(len(m.visible))
	case tea.KeyBackspace:
		if len(m.filter) > 0 {
			m.filter = m.filter[:len(m.filter)-1]
			m.applyFilter()
		}
	case tea.KeyCtrlU:
		m.filter = nil
		m.applyFilter()
	case tea.KeyRunes, tea.KeySpace:
		// Lo pegado podría ser una URI con secretos, y se vería en pantalla.
		if msg.Paste || msg.Alt {
			return m, nil
		}
		m.filter = append(m.filter, sanitizeRunes(msg.Runes)...)
		m.applyFilter()
	}
	return m, nil
}

func sanitizeRunes(runes []rune) []rune {
	return []rune(sanitize(string(runes)))
}

// applyFilter muestra las cuentas que contienen todas las palabras buscadas.
func (m *Model) applyFilter() {
	terms := strings.Fields(strings.ToLower(string(m.filter)))
	m.visible = m.visible[:0]
	for i, text := range m.labels {
		text = strings.ToLower(text)
		matches := true
		for _, term := range terms {
			if !strings.Contains(text, term) {
				matches = false
				break
			}
		}
		if matches {
			m.visible = append(m.visible, i)
		}
	}
	m.cursor, m.offset = 0, 0
}

func (m *Model) pageSize() int {
	height := m.height
	if height <= 0 {
		height = defaultHeight
	}
	return max(1, height-chromeLines)
}

func (m *Model) moveCursor(delta int) {
	m.cursor = max(0, min(m.cursor+delta, len(m.visible)-1))
	m.keepCursorVisible()
}

func (m *Model) keepCursorVisible() {
	page := m.pageSize()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+page {
		m.offset = m.cursor - page + 1
	}
	m.offset = max(0, min(m.offset, max(0, len(m.visible)-page)))
}

// mustWait indica si conviene esperar al código siguiente. Con periodos muy cortos
// no se espera, porque nunca habría un momento mejor.
func (m *Model) mustWait(e model.Entry, now time.Time) bool {
	remaining, err := totp.Remaining(now, e.Period)
	return err == nil && e.Period > 2*nearExpiry && remaining <= nearExpiry
}

func (m *Model) copySelected() {
	if len(m.visible) == 0 {
		return
	}
	i := m.visible[m.cursor]
	now := m.clock()
	if m.mustWait(m.entries[i], now) {
		m.pending = i
		m.status = fmt.Sprintf("Esperando el código nuevo de %s para copiarlo... (Esc cancela)", m.labels[i])
		return
	}
	m.pending = noneSelected
	m.copyNow(i, now)
}

func (m *Model) copyNow(i int, now time.Time) {
	e := m.entries[i]
	code, err := totp.Code(e.Secret, now, e.Period, e.Digits, e.Algorithm)
	if err != nil {
		m.status = "No se pudo generar el código."
		return
	}
	remaining, err := totp.Remaining(now, e.Period)
	if err != nil {
		m.status = "No se pudo generar el código."
		return
	}
	if err := m.clipboard.WriteAll(code); err != nil {
		m.status = "No se pudo usar el portapapeles."
		return
	}
	m.copied = code
	m.clearAt = now.Add(time.Duration(remaining) * time.Second)
	m.status = fmt.Sprintf("Copiado el código de %s. Se limpiará en %d s.", m.labels[i], remaining)
}

// View dibuja la pantalla. Los códigos se calculan solo para las filas visibles.
func (m *Model) View() string {
	var b strings.Builder
	fmt.Fprintf(&b, "piko2fa - %d de %d cuentas\n", len(m.visible), len(m.entries))
	fmt.Fprintf(&b, "Buscar: %s_\n\n", string(m.filter))

	now := m.clock()
	page := m.pageSize()
	end := min(m.offset+page, len(m.visible))
	for row := m.offset; row < end; row++ {
		b.WriteString(m.renderRow(row, now))
		b.WriteByte('\n')
	}
	switch {
	case len(m.entries) == 0:
		b.WriteString("No hay cuentas. Añádelas con piko2fa add o piko2fa import-ga.\n")
	case len(m.visible) == 0:
		b.WriteString("Ninguna cuenta coincide con la búsqueda.\n")
	}

	fmt.Fprintf(&b, "\n%s\n", m.status)
	b.WriteString("Flechas: mover | Enter: copiar | Esc: limpiar/salir | Ctrl+L: bloquear")
	return b.String()
}

func (m *Model) renderRow(row int, now time.Time) string {
	i := m.visible[row]
	e := m.entries[i]

	code, remaining := "------", 0
	if c, err := totp.Code(e.Secret, now, e.Period, e.Digits, e.Algorithm); err == nil {
		code = groupDigits(c)
	}
	if r, err := totp.Remaining(now, e.Period); err == nil {
		remaining = r
	}

	countdown := fmt.Sprintf("%3d s", remaining)
	if remaining <= nearExpiry {
		countdown = styleWarn + countdown + styleWarnOff
	}
	text := fmt.Sprintf("%-9s %s  %s", code, countdown, m.labels[i])
	if row == m.cursor {
		return "> " + styleReverse + text + styleReverseOff
	}
	return "  " + text
}

// groupDigits separa el código en dos grupos solo para leerlo mejor: lo que se
// copia no lleva el espacio.
func groupDigits(code string) string {
	half := len(code) / 2
	return code[:half] + " " + code[half:]
}
