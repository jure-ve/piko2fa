// Package cli implementa los comandos de piko2fa.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"piko2fa/internal/model"
	"piko2fa/internal/tui"
	"piko2fa/internal/vault"
)

// minPasswordLength es una protección mínima frente a contraseñas adivinables:
// el vault se puede atacar sin conexión si alguien copia el archivo.
const minPasswordLength = 12

// App contiene todo lo que los comandos usan del exterior, para poder probarlos
// sin terminal.
type App struct {
	Out        io.Writer
	Console    Console
	Stdin      io.Reader
	StdinPiped bool
	VaultPath  string
	Clipboard  Clipboard
	Now        func() time.Time
	Sleep      func(time.Duration)

	StdoutTerminal bool
	RunTUI         func(*tui.Model) error
}

// New prepara la aplicación para ejecutarse en un proceso real.
func New() (*App, error) {
	path, err := vault.DefaultPath()
	if err != nil {
		return nil, err
	}
	console, piped := newConsole()
	return &App{
		Out:        os.Stdout,
		Console:    console,
		Stdin:      os.Stdin,
		StdinPiped: piped,
		VaultPath:  path,
		Clipboard:  systemClipboard{},
		Now:        time.Now,
		Sleep:      time.Sleep,

		StdoutTerminal: stdoutIsTerminal(),
		RunTUI:         runTUI,
	}, nil
}

// Execute ejecuta el comando indicado por args.
func (a *App) Execute(args []string) error {
	root := &cobra.Command{
		Use:           "piko2fa",
		Short:         "Gestor 2FA (TOTP) con un vault cifrado local",
		Args:          rejectUnknownCommand,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	root.CompletionOptions.DisableDefaultCmd = true
	// Los errores de cobra citan lo que se escribió, y podría ser una URI.
	root.SetFlagErrorFunc(func(*cobra.Command, error) error {
		return errors.New("opción no válida; consulta --help")
	})
	root.SetOut(a.Out)
	root.SetErr(a.Out)
	root.SetArgs(args)
	root.AddCommand(
		a.initCommand(),
		a.addCommand(),
		a.listCommand(),
		a.codeCommand(),
		a.rmCommand(),
		a.importCommand(),
		a.passwdCommand(),
		a.exportCommand(),
		a.restoreCommand(),
		a.tuiCommand(),
	)
	return root.Execute()
}

// rejectArgs impide pasar secretos como argumentos, donde quedarían en el
// historial de la terminal y en la lista de procesos. No cita lo recibido.
func rejectArgs(_ *cobra.Command, args []string) error {
	if len(args) > 0 {
		return errors.New("este comando no acepta argumentos; las URIs no se pasan por la línea de comandos, porque quedarían en el historial")
	}
	return nil
}

// rejectUnknownCommand no cita lo recibido, que podría ser una URI.
func rejectUnknownCommand(_ *cobra.Command, args []string) error {
	if len(args) > 0 {
		return errors.New("comando desconocido; consulta piko2fa --help")
	}
	return nil
}

func argCount(minimum, maximum int) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) < minimum || len(args) > maximum {
			return errors.New("número de argumentos incorrecto; consulta --help")
		}
		return nil
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func (a *App) printf(format string, args ...any) {
	fmt.Fprintf(a.Out, format, args...)
}

func (a *App) confirm(prompt string) (bool, error) {
	answer, err := a.Console.ReadLine(prompt + " [s/N]: ")
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "s", "si", "sí", "y", "yes":
		return true, nil
	}
	return false, nil
}

func (a *App) vaultExists() (bool, error) {
	_, err := os.Stat(a.VaultPath)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("comprobar el vault: %w", err)
}

func (a *App) requireVault() error {
	exists, err := a.vaultExists()
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("todavía no hay vault; créalo con: piko2fa init")
	}
	return nil
}

// readNewPassword pide dos veces una contraseña nueva y comprueba que sea válida.
func (a *App) readNewPassword(prompt string) ([]byte, error) {
	password, err := a.Console.ReadSecret(prompt + ": ")
	if err != nil {
		return nil, err
	}
	if err := validatePassword(password); err != nil {
		clear(password)
		return nil, err
	}
	repeated, err := a.Console.ReadSecret("Repítela: ")
	if err != nil {
		clear(password)
		return nil, err
	}
	defer clear(repeated)
	if !slices.Equal(password, repeated) {
		clear(password)
		return nil, errors.New("las contraseñas no coinciden")
	}
	return password, nil
}

// validatePassword admite solo ASCII imprimible: otros caracteres pueden
// codificarse distinto según el teclado o el sistema, y el vault no abriría en
// otro equipo.
func validatePassword(password []byte) error {
	if len(password) < minPasswordLength {
		return fmt.Errorf("la contraseña debe tener al menos %d caracteres", minPasswordLength)
	}
	for _, c := range password {
		if c < 0x20 || c > 0x7e {
			return errors.New("la contraseña solo puede usar caracteres ASCII (sin ñ ni acentos)")
		}
	}
	return nil
}

// withVault pide la contraseña, abre el vault y ejecuta fn. La contraseña se
// pide antes de tomar el bloqueo, para no retenerlo mientras se escribe.
func (a *App) withVault(fn func(s *vault.FileStore, password []byte) error) error {
	if err := a.requireVault(); err != nil {
		return err
	}
	password, err := a.Console.ReadSecret("Contraseña maestra: ")
	if err != nil {
		return err
	}
	defer clear(password)

	s, err := vault.Open(a.VaultPath)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Load(password); err != nil {
		return err
	}
	return fn(s, password)
}

func label(name, issuer string) string {
	return model.Entry{Name: name, Issuer: issuer}.Label()
}

func sorted(entries []model.Entry) []model.Entry {
	out := slices.Clone(entries)
	slices.SortStableFunc(out, func(x, y model.Entry) int {
		return strings.Compare(strings.ToLower(label(x.Name, x.Issuer)), strings.ToLower(label(y.Name, y.Issuer)))
	})
	return out
}

// match busca las cuentas de una consulta. Un ID o una etiqueta "Emisor:cuenta"
// exactos eliminan la ambigüedad, y una coincidencia exacta con el nombre o el
// emisor tiene prioridad sobre las parciales.
func match(s *vault.FileStore, query string) []model.Entry {
	all := s.List()
	exact := func(same func(model.Entry) bool) []model.Entry {
		var found []model.Entry
		for _, e := range all {
			if same(e) {
				found = append(found, e)
			}
		}
		return found
	}

	if found := exact(func(e model.Entry) bool {
		return e.ID == query || strings.EqualFold(label(e.Name, e.Issuer), query)
	}); len(found) > 0 {
		return found
	}
	if found := exact(func(e model.Entry) bool {
		return strings.EqualFold(e.Name, query) || strings.EqualFold(e.Issuer, query)
	}); len(found) == 1 {
		return found
	}
	return sorted(s.Find(query))
}

// matchOne exige exactamente una cuenta y, si hay varias, las muestra con su ID
// para poder elegir.
func (a *App) matchOne(s *vault.FileStore, query string) (model.Entry, error) {
	found := match(s, query)
	switch len(found) {
	case 0:
		return model.Entry{}, errors.New("ninguna cuenta coincide con la consulta")
	case 1:
		return found[0], nil
	}
	for _, e := range found {
		a.printf("%s  (ID %s)\n", label(e.Name, e.Issuer), e.ID)
	}
	return model.Entry{}, fmt.Errorf("%d cuentas coinciden; precisa la consulta con Emisor:cuenta o con el ID", len(found))
}
