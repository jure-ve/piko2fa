package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"piko2fa/internal/tui"
)

// Console lee lo que escribe el usuario. Siempre lee de la terminal, aunque
// stdin venga de una tubería.
type Console interface {
	// ReadSecret lee una línea sin mostrarla.
	ReadSecret(prompt string) ([]byte, error)
	// ReadLine lee una línea visible.
	ReadLine(prompt string) (string, error)
}

// Clipboard accede al portapapeles del sistema.
type Clipboard interface {
	ReadAll() (string, error)
	WriteAll(text string) error
}

type systemClipboard struct{}

func (systemClipboard) ReadAll() (string, error)   { return clipboard.ReadAll() }
func (systemClipboard) WriteAll(text string) error { return clipboard.WriteAll(text) }

var errNoTerminal = errors.New("hace falta una terminal interactiva para leer la contraseña; en Git Bash usa PowerShell o ejecuta el comando con winpty")

// newConsole devuelve la consola y si stdin es una tubería. Con stdin en una
// tubería y stderr en una terminal se lee directamente de la terminal. Sin
// ninguna de las dos (por ejemplo, mintty) se devuelve un error en vez de
// arriesgarse a mostrar la contraseña o a quedarse esperando para siempre.
func newConsole() (Console, bool) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return &terminal{file: os.Stdin}, false
	}
	if term.IsTerminal(int(os.Stderr.Fd())) {
		return &terminal{}, true
	}
	return noTerminal{}, true
}

func stdoutIsTerminal() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// runTUI usa la pantalla alternativa: al salir, los códigos no quedan en el
// historial de la terminal.
func runTUI(m *tui.Model) error {
	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		return errors.New("no se pudo usar la interfaz en esta terminal")
	}
	return nil
}

type noTerminal struct{}

func (noTerminal) ReadSecret(string) ([]byte, error) { return nil, errNoTerminal }
func (noTerminal) ReadLine(string) (string, error)   { return "", errNoTerminal }

type terminal struct {
	file *os.File
}

func (t *terminal) input() (*os.File, error) {
	if t.file != nil {
		return t.file, nil
	}
	name := "/dev/tty"
	if runtime.GOOS == "windows" {
		name = "CONIN$"
	}
	f, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		return nil, errNoTerminal
	}
	t.file = f
	return f, nil
}

func (t *terminal) ReadSecret(prompt string) ([]byte, error) {
	f, err := t.input()
	if err != nil {
		return nil, err
	}
	fd := int(f.Fd())

	// Sin esto, Ctrl+C dejaría la terminal sin eco.
	state, err := term.GetState(fd)
	if err != nil {
		return nil, errNoTerminal
	}
	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt)
	defer signal.Stop(interrupted)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-interrupted:
			term.Restore(fd, state)
			fmt.Fprintln(os.Stderr)
			os.Exit(130)
		case <-done:
		}
	}()

	fmt.Fprint(os.Stderr, prompt)
	secret, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, errors.New("no se pudo leer de la terminal")
	}
	return secret, nil
}

func (t *terminal) ReadLine(prompt string) (string, error) {
	f, err := t.input()
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, prompt)

	var line strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			line.WriteByte(buf[0])
		}
		if err == io.EOF {
			if line.Len() == 0 {
				return "", errors.New("no se recibió respuesta")
			}
			break
		}
		if err != nil {
			return "", errors.New("no se pudo leer de la terminal")
		}
	}
	return strings.TrimRight(line.String(), "\r"), nil
}
