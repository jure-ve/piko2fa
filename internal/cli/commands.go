package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"piko2fa/internal/gamigration"
	"piko2fa/internal/model"
	"piko2fa/internal/otpauth"
	"piko2fa/internal/qrimage"
	"piko2fa/internal/totp"
	"piko2fa/internal/tui"
	"piko2fa/internal/vault"
)

func (a *App) initCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Crea el vault",
		Args:  rejectArgs,
		RunE: func(*cobra.Command, []string) error {
			exists, err := a.vaultExists()
			if err != nil {
				return err
			}
			if exists {
				return vault.ErrExists
			}
			password, err := a.readNewPassword("Contraseña maestra nueva")
			if err != nil {
				return err
			}
			defer clear(password)

			s, err := vault.Open(a.VaultPath)
			if err != nil {
				return err
			}
			defer s.Close()
			if err := s.Init(password); err != nil {
				return err
			}
			a.printf("Vault creado en %s\n", a.VaultPath)
			a.printf("Guarda la contraseña en un lugar seguro: sin ella, el vault no se puede recuperar.\n")
			return nil
		},
	}
}

func (a *App) addCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "add",
		Short: "Añade una cuenta, con su URI otpauth:// por entrada oculta o stdin, o a mano",
		Args:  rejectArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := a.requireVault(); err != nil {
				return err
			}
			e, err := a.readEntry()
			if err != nil {
				return err
			}
			defer clear(e.Secret)

			return a.withVault(func(s *vault.FileStore, password []byte) error {
				d := gamigration.Dedupe([]model.Entry{e}, s.List())
				if len(d.Duplicates) > 0 {
					a.printf("La cuenta %s ya existe.\n", label(e.Name, e.Issuer))
					return nil
				}
				if len(d.Conflicts) > 0 {
					existing := d.Conflicts[0].Existing
					ok, err := a.confirm(fmt.Sprintf("%s usa el mismo secreto. ¿Añadir %s de todos modos?",
						label(existing.Name, existing.Issuer), label(e.Name, e.Issuer)))
					if err != nil {
						return err
					}
					if !ok {
						a.printf("Cancelado.\n")
						return nil
					}
				}
				if err := s.Add(e); err != nil {
					return err
				}
				if err := s.Save(password); err != nil {
					return err
				}
				a.printf("Cuenta %s añadida.\n", label(e.Name, e.Issuer))
				return nil
			})
		},
	}
}

func (a *App) readEntry() (model.Entry, error) {
	if a.StdinPiped {
		data, err := io.ReadAll(a.Stdin)
		if err != nil {
			return model.Entry{}, errors.New("no se pudo leer stdin")
		}
		defer clear(data)
		return otpauth.Parse(string(data))
	}

	uri, err := a.Console.ReadSecret("URI otpauth:// (vacía para escribir los datos a mano): ")
	if err != nil {
		return model.Entry{}, err
	}
	defer clear(uri)
	if len(bytes.TrimSpace(uri)) > 0 {
		return otpauth.Parse(string(uri))
	}

	issuer, err := a.Console.ReadLine("Emisor: ")
	if err != nil {
		return model.Entry{}, err
	}
	name, err := a.Console.ReadLine("Cuenta: ")
	if err != nil {
		return model.Entry{}, err
	}
	encoded, err := a.Console.ReadSecret("Secreto en base32: ")
	if err != nil {
		return model.Entry{}, err
	}
	defer clear(encoded)
	secret, err := otpauth.DecodeSecret(string(encoded))
	if err != nil {
		return model.Entry{}, err
	}
	return model.New(strings.TrimSpace(name), strings.TrimSpace(issuer), secret,
		model.DefaultAlgorithm, model.DefaultDigits, model.DefaultPeriod)
}

func (a *App) listCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list [filtro]",
		Short: "Muestra las cuentas, sin secretos ni códigos",
		Args:  argCount(0, 1),
		RunE: func(_ *cobra.Command, args []string) error {
			return a.withVault(func(s *vault.FileStore, _ []byte) error {
				query := ""
				if len(args) == 1 {
					query = args[0]
				}
				found := sorted(s.Find(query))
				for _, e := range found {
					a.printf("%s\n", label(e.Name, e.Issuer))
				}
				a.printf("%s\n", plural(len(found), "cuenta", "cuentas"))
				return nil
			})
		},
	}
}

func (a *App) codeCommand() *cobra.Command {
	var all, copyCode bool
	cmd := &cobra.Command{
		Use:   "code [consulta]",
		Short: "Muestra el código actual de una cuenta, o de todas con --all",
		Args:  argCount(0, 1),
		RunE: func(_ *cobra.Command, args []string) error {
			if all && (len(args) > 0 || copyCode) {
				return errors.New("--all no se combina con una consulta ni con --copy")
			}
			if !all && len(args) == 0 {
				return errors.New("indica una consulta, o usa --all")
			}

			var code string
			var remaining int
			err := a.withVault(func(s *vault.FileStore, _ []byte) error {
				if all {
					return a.printAllCodes(s)
				}
				e, err := a.matchOne(s, args[0])
				if err != nil {
					return err
				}
				now := a.Now()
				if code, err = totp.Code(e.Secret, now, e.Period, e.Digits, e.Algorithm); err != nil {
					return err
				}
				if remaining, err = totp.Remaining(now, e.Period); err != nil {
					return err
				}
				a.printf("%s\n%s  (quedan %d s)\n", label(e.Name, e.Issuer), code, remaining)
				return nil
			})
			if err != nil || !copyCode {
				return err
			}
			// Aquí el vault ya está cerrado: esperar no retiene el bloqueo.
			return a.copyUntilExpired(code, remaining)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "muestra los códigos de todas las cuentas")
	cmd.Flags().BoolVar(&copyCode, "copy", false, "copia el código y lo limpia del portapapeles al expirar")
	return cmd
}

func (a *App) printAllCodes(s *vault.FileStore) error {
	now := a.Now()
	w := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
	for _, e := range sorted(s.List()) {
		code, err := totp.Code(e.Secret, now, e.Period, e.Digits, e.Algorithm)
		if err != nil {
			return err
		}
		remaining, err := totp.Remaining(now, e.Period)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s\t%s\t%d s\n", label(e.Name, e.Issuer), code, remaining)
	}
	return w.Flush()
}

// copyUntilExpired no borra lo que el usuario haya copiado mientras tanto.
func (a *App) copyUntilExpired(code string, remaining int) error {
	if err := a.Clipboard.WriteAll(code); err != nil {
		return errors.New("no se pudo usar el portapapeles")
	}
	a.printf("Copiado. Se limpiará en %d s; si sales antes con Ctrl+C, no se limpiará.\n", remaining)
	a.Sleep(time.Duration(remaining) * time.Second)

	current, err := a.Clipboard.ReadAll()
	if err != nil {
		return errors.New("no se pudo limpiar el portapapeles")
	}
	if current != code {
		return nil
	}
	if err := a.Clipboard.WriteAll(""); err != nil {
		return errors.New("no se pudo limpiar el portapapeles")
	}
	a.printf("Portapapeles limpio. Si usas el historial de Windows (Win+V), allí puede seguir el código.\n")
	return nil
}

func (a *App) tuiCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Abre la interfaz interactiva: buscar, ver códigos en vivo y copiar",
		Args:  rejectArgs,
		RunE: func(*cobra.Command, []string) error {
			// Sin terminal, los códigos acabarían en un archivo o una tubería.
			if a.StdinPiped || !a.StdoutTerminal {
				return errors.New("la interfaz necesita una terminal interactiva; sin ella usa piko2fa code")
			}
			for {
				locked, err := a.runTUISession()
				if err != nil || !locked {
					return err
				}
				a.printf("Bloqueado. Escribe la contraseña para continuar, o pulsa Ctrl+C para salir.\n")
			}
		},
	}
}

// runTUISession abre una sesión e indica si terminó por un bloqueo. La contraseña
// y el bloqueo del vault se sueltan antes de empezar: la interfaz solo necesita
// una copia de las cuentas, y mientras tanto funcionan los demás comandos.
func (a *App) runTUISession() (locked bool, err error) {
	var entries []model.Entry
	err = a.withVault(func(s *vault.FileStore, _ []byte) error {
		entries = sorted(s.List())
		for i := range entries {
			entries[i].Secret = bytes.Clone(entries[i].Secret)
		}
		return nil
	})
	if err != nil {
		return false, err
	}

	m := tui.New(entries, a.Clipboard, a.Now)
	defer func() {
		if closeErr := m.Close(); closeErr != nil {
			a.printf("Aviso: %v.\n", closeErr)
		}
	}()
	if err := a.RunTUI(m); err != nil {
		return false, err
	}
	return m.Locked(), nil
}

func (a *App) rmCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <consulta>",
		Short: "Elimina una cuenta, previa confirmación",
		Args:  argCount(1, 1),
		RunE: func(_ *cobra.Command, args []string) error {
			return a.withVault(func(s *vault.FileStore, password []byte) error {
				e, err := a.matchOne(s, args[0])
				if err != nil {
					return err
				}
				ok, err := a.confirm(fmt.Sprintf("¿Eliminar %s?", label(e.Name, e.Issuer)))
				if err != nil {
					return err
				}
				if !ok {
					a.printf("Cancelado.\n")
					return nil
				}
				name := label(e.Name, e.Issuer)
				if err := s.Remove(e.ID); err != nil {
					return err
				}
				if err := s.Save(password); err != nil {
					return err
				}
				a.printf("Cuenta %s eliminada.\n", name)
				return nil
			})
		},
	}
}

func (a *App) importCommand() *cobra.Command {
	var file string
	var qr bool
	cmd := &cobra.Command{
		Use:   "import-ga [--qr imagen...]",
		Short: "Importa desde Google Authenticator: URIs por entrada oculta, stdin o --file, o imágenes de QR con --qr",
		Args: func(cmd *cobra.Command, args []string) error {
			if !qr {
				return rejectArgs(cmd, args)
			}
			for _, arg := range args {
				if strings.Contains(arg, "://") {
					return rejectArgs(cmd, args)
				}
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			if qr && file != "" {
				return errors.New("--qr no se combina con --file")
			}
			if qr && len(args) == 0 {
				return errors.New("indica al menos una imagen, por ejemplo: piko2fa import-ga --qr qr\\*.png")
			}
			if err := a.requireVault(); err != nil {
				return err
			}

			var uris []string
			var err error
			if qr {
				uris, err = a.readQRImages(args)
			} else {
				uris, err = a.readMigrationURIs(file)
			}
			if err != nil {
				return err
			}
			err = a.withVault(func(s *vault.FileStore, password []byte) error {
				return a.runImport(s, password, uris)
			})
			if file != "" {
				a.printf("Recuerda borrar %s: contiene secretos en claro.\n", file)
			}
			if qr {
				a.printf("Recuerda borrar las imágenes y vaciar la papelera: contienen secretos en claro.\n")
			}
			return err
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "archivo con una URI otpauth-migration:// por línea")
	cmd.Flags().BoolVar(&qr, "qr", false, "lee las URIs de imágenes de QR (PNG o JPEG); admite comodines")
	return cmd
}

// readQRImages lee los QR indicados. Las imágenes ilegibles se informan sin
// detener el resto: la vista previa mostrará qué QR del lote faltan.
func (a *App) readQRImages(patterns []string) ([]string, error) {
	var paths []string
	for _, pattern := range patterns {
		// PowerShell no expande los comodines; lo hace cada programa.
		if !strings.ContainsAny(pattern, "*?[") {
			paths = append(paths, pattern)
			continue
		}
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			return nil, fmt.Errorf("ninguna imagen coincide con %s", pattern)
		}
		paths = append(paths, matches...)
	}

	var uris []string
	for _, path := range paths {
		text, err := qrimage.Decode(path)
		if err != nil {
			a.printf("No se pudo leer %s: %v\n", path, err)
			continue
		}
		uris = append(uris, text)
	}
	if len(uris) == 0 {
		return nil, errors.New("no se pudo leer ningún QR; repite la foto más de cerca y con buena luz, o léelo con un lector sin conexión y pega la URI en piko2fa import-ga")
	}
	if len(uris) < len(paths) {
		a.printf("Se leyeron %d de %d imágenes. Puedes repetir las que fallaron más adelante.\n", len(uris), len(paths))
	}
	return uris, nil
}

func (a *App) readMigrationURIs(file string) ([]string, error) {
	var uris []string
	switch {
	case file != "":
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, errors.New("no se pudo leer el archivo")
		}
		defer clear(data)
		if uris, err = splitURIs(data); err != nil {
			return nil, err
		}
	case a.StdinPiped:
		data, err := io.ReadAll(a.Stdin)
		if err != nil {
			return nil, errors.New("no se pudo leer stdin")
		}
		defer clear(data)
		if uris, err = splitURIs(data); err != nil {
			return nil, err
		}
	default:
		for {
			uri, err := a.Console.ReadSecret(fmt.Sprintf("URI %d (vacía para terminar): ", len(uris)+1))
			if err != nil {
				return nil, err
			}
			text := strings.TrimSpace(string(uri))
			clear(uri)
			if text == "" {
				break
			}
			uris = append(uris, text)
		}
	}
	if len(uris) == 0 {
		return nil, errors.New("no se recibió ninguna URI")
	}
	return uris, nil
}

// splitURIs separa las líneas. Tiene en cuenta las marcas de orden de bytes,
// porque PowerShell 5.1 puede guardar los archivos en UTF-16.
func splitURIs(data []byte) ([]string, error) {
	if bytes.HasPrefix(data, []byte{0xff, 0xfe}) || bytes.HasPrefix(data, []byte{0xfe, 0xff}) {
		return nil, errors.New("el contenido está en UTF-16; guárdalo como UTF-8")
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})

	var uris []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			uris = append(uris, line)
		}
	}
	return uris, nil
}

func (a *App) runImport(s *vault.FileStore, password []byte, uris []string) error {
	r := gamigration.Import(uris, s.List())
	defer zeroImport(r)
	a.printImportPreview(r)

	if len(r.Entries)+len(r.Conflicts) == 0 {
		a.printf("No hay cuentas nuevas que importar.\n")
		return nil
	}

	if !r.Complete() {
		a.printf("La importación está incompleta: se puede continuar y añadir el resto más adelante.\n")
	}
	ok, err := a.confirm(fmt.Sprintf("¿Importar %s?", plural(len(r.Entries), "cuenta nueva", "cuentas nuevas")))
	if err != nil {
		return err
	}
	if !ok {
		a.printf("Cancelado.\n")
		return nil
	}

	added := 0
	for _, e := range r.Entries {
		if err := s.Add(e); err != nil {
			return err
		}
		added++
	}
	for _, c := range r.Conflicts {
		ok, err := a.confirm(fmt.Sprintf("%s usa el mismo secreto. ¿Añadir %s de todos modos?",
			label(c.Existing.Name, c.Existing.Issuer), label(c.Incoming.Name, c.Incoming.Issuer)))
		if err != nil {
			return err
		}
		if ok {
			if err := s.Add(c.Incoming); err != nil {
				return err
			}
			added++
		}
	}

	if added == 0 {
		a.printf("No se importó ninguna cuenta.\n")
		return nil
	}
	if err := s.Save(password); err != nil {
		return err
	}
	a.printf("%s.\n", plural(added, "cuenta importada", "cuentas importadas"))
	return nil
}

func zeroImport(r gamigration.Result) {
	for _, e := range r.Entries {
		clear(e.Secret)
	}
	for _, e := range r.Duplicates {
		clear(e.Secret)
	}
	for _, c := range r.Conflicts {
		clear(c.Incoming.Secret)
	}
}

func (a *App) printImportPreview(r gamigration.Result) {
	a.printf("Recibidas: %d\nNuevas: %d\nYa presentes: %d\nConflictos: %d\nRechazadas: %d\n",
		r.Total, len(r.Entries), len(r.Duplicates), len(r.Conflicts), len(r.Rejected))

	for _, b := range r.Batches {
		a.printf("Exportación %d: %d de %d QR leídos\n", b.ID, len(b.Received), b.Size)
		if len(b.Missing) > 0 {
			a.printf("  Faltan los QR: %s\n", oneBased(b.Missing))
		}
		if len(b.Repeated) > 0 {
			a.printf("  Leídos más de una vez: %s\n", oneBased(b.Repeated))
		}
	}
	for _, invalid := range r.InvalidURIs {
		a.printf("URI %d no válida: %v\n", invalid.Index+1, invalid.Err)
	}
	for _, rejected := range r.Rejected {
		a.printf("Rechazada %s: %s\n", label(rejected.Name, rejected.Issuer), rejected.Reason)
	}
	for _, w := range r.Warnings {
		if account := label(w.Name, w.Issuer); account != "" {
			a.printf("Aviso (%s): %s\n", account, w.Message)
		} else {
			a.printf("Aviso: %s\n", w.Message)
		}
	}
}

func oneBased(indexes []int) string {
	parts := make([]string, len(indexes))
	for i, index := range indexes {
		parts[i] = fmt.Sprint(index + 1)
	}
	return strings.Join(parts, ", ")
}

func (a *App) passwdCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "passwd",
		Short: "Cambia la contraseña maestra del vault y de su .bak",
		Args:  rejectArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := a.requireVault(); err != nil {
				return err
			}
			current, err := a.Console.ReadSecret("Contraseña actual: ")
			if err != nil {
				return err
			}
			defer clear(current)
			updated, err := a.readNewPassword("Contraseña nueva")
			if err != nil {
				return err
			}
			defer clear(updated)

			s, err := vault.Open(a.VaultPath)
			if err != nil {
				return err
			}
			defer s.Close()
			if err := s.ChangePassword(current, updated); err != nil {
				return err
			}
			a.printf("Contraseña cambiada.\n")
			a.printf("Los respaldos exportados antes siguen abriéndose con la contraseña anterior.\n")
			return nil
		},
	}
}

func (a *App) exportCommand() *cobra.Command {
	var encrypted, plaintext string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Exporta un respaldo cifrado con --encrypted, o en claro con --plaintext",
		Args:  rejectArgs,
		RunE: func(*cobra.Command, []string) error {
			if (encrypted == "") == (plaintext == "") {
				return errors.New("indica --encrypted o --plaintext, solo uno de los dos")
			}
			return a.withVault(func(s *vault.FileStore, password []byte) error {
				if encrypted != "" {
					if err := s.Export(encrypted, password); err != nil {
						return err
					}
					a.printf("Respaldo cifrado en %s. Se abre con la contraseña maestra actual.\n", encrypted)
					return nil
				}
				return a.exportPlaintext(s, plaintext)
			})
		},
	}
	cmd.Flags().StringVar(&encrypted, "encrypted", "", "archivo de destino del respaldo cifrado")
	cmd.Flags().StringVar(&plaintext, "plaintext", "", "archivo de destino con todas las claves EN CLARO")
	return cmd
}

func (a *App) exportPlaintext(s *vault.FileStore, path string) error {
	const confirmation = "EXPORTAR"
	answer, err := a.Console.ReadLine(fmt.Sprintf("El archivo contendrá todas tus claves EN CLARO. Escribe %s para continuar: ", confirmation))
	if err != nil {
		return err
	}
	if strings.TrimSpace(answer) != confirmation {
		a.printf("Cancelado.\n")
		return nil
	}

	var content strings.Builder
	entries := sorted(s.List())
	for _, e := range entries {
		uri, err := otpauth.Format(e)
		if err != nil {
			return err
		}
		content.WriteString(uri + "\n")
	}

	// O_EXCL impide reemplazar un archivo existente.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return vault.ErrExists
	}
	if err != nil {
		return errors.New("no se pudo crear el archivo")
	}
	if _, err := f.WriteString(content.String()); err != nil {
		f.Close()
		os.Remove(path)
		return errors.New("no se pudo escribir el archivo")
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return errors.New("no se pudo escribir el archivo")
	}
	a.printf("%s en claro en %s. Bórralo en cuanto termines.\n", plural(len(entries), "cuenta exportada", "cuentas exportadas"), path)
	return nil
}

func (a *App) restoreCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "restore <archivo>",
		Short: "Restaura el vault desde un respaldo cifrado o desde su .bak",
		Args:  argCount(1, 1),
		RunE: func(_ *cobra.Command, args []string) error {
			password, err := a.Console.ReadSecret("Contraseña del respaldo: ")
			if err != nil {
				return err
			}
			defer clear(password)

			s, err := vault.Open(a.VaultPath)
			if err != nil {
				return err
			}
			defer s.Close()

			var confirmErr error
			result, err := s.Restore(args[0], password, func(entries int, replacing bool) bool {
				if !replacing {
					return true
				}
				ok, err := a.confirm(fmt.Sprintf("Esto reemplazará el vault actual por un respaldo de %s. ¿Continuar?", plural(entries, "cuenta", "cuentas")))
				confirmErr = err
				return ok
			})
			if confirmErr != nil {
				return confirmErr
			}
			if errors.Is(err, vault.ErrCanceled) {
				a.printf("Cancelado.\n")
				return nil
			}
			if err != nil {
				return err
			}

			a.printf("%s. El vault usa ahora la contraseña del respaldo.\n", plural(result.Entries, "cuenta restaurada", "cuentas restauradas"))
			if result.Previous != "" {
				a.printf("El vault anterior se guardó en %s\n", result.Previous)
			}
			return nil
		},
	}
}
