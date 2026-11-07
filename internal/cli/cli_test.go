package cli

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"piko2fa/internal/tui"
	"piko2fa/internal/vault"
)

// Contraseñas y claves de estos tests son falsas.
const (
	testPassword  = "clave-de-prueba-1234"
	otherPassword = "otra-clave-de-prueba-5678"

	rfcBase32  = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	fakeBase32 = "JBSWY3DPEHPK3PXP"
)

type fakeConsole struct {
	secrets []string
	lines   []string
	given   [][]byte
	prompts []string
}

func (c *fakeConsole) ReadSecret(prompt string) ([]byte, error) {
	c.prompts = append(c.prompts, prompt)
	if len(c.secrets) == 0 {
		return nil, errors.New("test: no quedan secretos para: " + prompt)
	}
	secret := []byte(c.secrets[0])
	c.secrets = c.secrets[1:]
	c.given = append(c.given, secret)
	return secret, nil
}

func (c *fakeConsole) ReadLine(prompt string) (string, error) {
	c.prompts = append(c.prompts, prompt)
	if len(c.lines) == 0 {
		return "", errors.New("test: no quedan líneas para: " + prompt)
	}
	line := c.lines[0]
	c.lines = c.lines[1:]
	return line, nil
}

type fakeClipboard struct {
	content string
	writes  []string
	onSleep string // lo que "copia" el usuario mientras se espera
}

func (c *fakeClipboard) ReadAll() (string, error) { return c.content, nil }
func (c *fakeClipboard) WriteAll(text string) error {
	c.content = text
	c.writes = append(c.writes, text)
	return nil
}

type env struct {
	t         *testing.T
	path      string
	out       bytes.Buffer
	stdin     string
	piped     bool
	console   *fakeConsole
	clipboard *fakeClipboard
	slept     time.Duration
	now       time.Time

	noStdoutTerminal bool
	runTUI           func(*tui.Model) error
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return &env{
		t:         t,
		path:      filepath.Join(t.TempDir(), "vault.bin"),
		clipboard: &fakeClipboard{},
		now:       time.Unix(59, 0),
	}
}

// run ejecuta un comando con las respuestas indicadas y comprueba que las haya
// consumido todas, para detectar preguntas de más o de menos.
func (e *env) run(secrets, lines []string, args ...string) (string, error) {
	e.t.Helper()
	e.out.Reset()
	e.console = &fakeConsole{secrets: secrets, lines: lines}
	app := &App{
		Out:        &e.out,
		Console:    e.console,
		Stdin:      strings.NewReader(e.stdin),
		StdinPiped: e.piped,
		VaultPath:  e.path,
		Clipboard:  e.clipboard,
		Now:        func() time.Time { return e.now },
		Sleep: func(d time.Duration) {
			e.slept = d
			if e.clipboard.onSleep != "" {
				e.clipboard.content = e.clipboard.onSleep
			}
		},
		StdoutTerminal: !e.noStdoutTerminal,
		RunTUI:         e.runTUI,
	}
	err := app.Execute(args)
	return e.out.String(), err
}

func (e *env) mustRun(secrets, lines []string, args ...string) string {
	e.t.Helper()
	out, err := e.run(secrets, lines, args...)
	if err != nil {
		e.t.Fatalf("%v: %v\n%s", args, err, out)
	}
	if len(e.console.secrets) > 0 || len(e.console.lines) > 0 {
		e.t.Fatalf("%v: respuestas sin usar: %v %v", args, e.console.secrets, e.console.lines)
	}
	return out
}

func (e *env) init() {
	e.t.Helper()
	e.mustRun([]string{testPassword, testPassword}, nil, "init")
}

func (e *env) add(uri string) {
	e.t.Helper()
	e.mustRun([]string{uri, testPassword}, nil, "add")
}

func (e *env) list() string {
	e.t.Helper()
	return e.mustRun([]string{testPassword}, nil, "list")
}

func totpURI(issuer, name, base32 string) string {
	return "otpauth://totp/" + url.PathEscape(issuer) + ":" + url.PathEscape(name) + "?secret=" + base32 + "&issuer=" + url.QueryEscape(issuer)
}

type gaAccount struct {
	name, issuer string
	secret       []byte
	otpType      uint64
}

func migrationURI(batchID int32, index, size int, accounts ...gaAccount) string {
	var b []byte
	for _, a := range accounts {
		var p []byte
		p = protowire.AppendTag(p, 1, protowire.BytesType)
		p = protowire.AppendBytes(p, a.secret)
		p = protowire.AppendTag(p, 2, protowire.BytesType)
		p = protowire.AppendString(p, a.name)
		p = protowire.AppendTag(p, 3, protowire.BytesType)
		p = protowire.AppendString(p, a.issuer)
		p = protowire.AppendTag(p, 4, protowire.VarintType)
		p = protowire.AppendVarint(p, 1)
		p = protowire.AppendTag(p, 5, protowire.VarintType)
		p = protowire.AppendVarint(p, 1)
		otpType := a.otpType
		if otpType == 0 {
			otpType = 2
		}
		p = protowire.AppendTag(p, 6, protowire.VarintType)
		p = protowire.AppendVarint(p, otpType)

		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendBytes(b, p)
	}
	for _, f := range []struct {
		num   protowire.Number
		value int64
	}{{3, int64(size)}, {4, int64(index)}, {5, int64(batchID)}} {
		b = protowire.AppendTag(b, f.num, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(f.value))
	}
	return "otpauth-migration://offline?data=" + url.QueryEscape(base64.StdEncoding.EncodeToString(b))
}

func ga(name, issuer string) gaAccount {
	return gaAccount{name: name, issuer: issuer, secret: []byte("secreto-falso-" + name)}
}

func shouldContain(t *testing.T, out string, parts ...string) {
	t.Helper()
	for _, part := range parts {
		if !strings.Contains(out, part) {
			t.Errorf("la salida no contiene %q:\n%s", part, out)
		}
	}
}

func shouldNotContain(t *testing.T, out string, parts ...string) {
	t.Helper()
	for _, part := range parts {
		if strings.Contains(out, part) {
			t.Errorf("la salida contiene %q:\n%s", part, out)
		}
	}
}

func TestInit(t *testing.T) {
	e := newEnv(t)
	out := e.mustRun([]string{testPassword, testPassword}, nil, "init")
	shouldContain(t, out, "Vault creado", e.path)
	if _, err := os.Stat(e.path); err != nil {
		t.Fatal(err)
	}
	if got := e.list(); !strings.Contains(got, "0 cuentas") {
		t.Errorf("list = %s", got)
	}
}

func TestInitRejectsBadPasswords(t *testing.T) {
	tests := []struct {
		name    string
		secrets []string
	}{
		{"vacía", []string{""}},
		{"corta", []string{"abc123"}},
		{"con ñ", []string{"contraseña-larga-123"}},
		{"con acento", []string{"contrasena-larga-é23"}},
		{"con control", []string{"contrasena-larga\t123"}},
		{"no coinciden", []string{testPassword, otherPassword}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			if _, err := e.run(tt.secrets, nil, "init"); err == nil {
				t.Error("no hubo error")
			}
			if _, err := os.Stat(e.path); err == nil {
				t.Error("se creó el vault")
			}
		})
	}
}

func TestInitRefusesExistingVaultWithoutAsking(t *testing.T) {
	e := newEnv(t)
	e.init()
	before, _ := os.ReadFile(e.path)

	if _, err := e.run(nil, nil, "init"); !errors.Is(err, vault.ErrExists) {
		t.Errorf("err = %v", err)
	}
	if after, _ := os.ReadFile(e.path); !bytes.Equal(before, after) {
		t.Error("el vault cambió")
	}
}

func TestCommandsRequireVaultBeforeAskingPassword(t *testing.T) {
	for _, args := range [][]string{
		{"add"}, {"list"}, {"code", "x"}, {"code", "--all"}, {"rm", "x"}, {"import-ga"}, {"passwd"}, {"export", "--encrypted", "x"},
	} {
		e := newEnv(t)
		_, err := e.run(nil, nil, args...)
		if err == nil || !strings.Contains(err.Error(), "piko2fa init") {
			t.Errorf("%v: err = %v", args, err)
		}
		if len(e.console.prompts) != 0 {
			t.Errorf("%v: preguntó %v", args, e.console.prompts)
		}
	}
}

func TestWrongPassword(t *testing.T) {
	e := newEnv(t)
	e.init()
	_, err := e.run([]string{otherPassword}, nil, "list")
	if !errors.Is(err, vault.ErrInvalid) {
		t.Errorf("err = %v", err)
	}
}

// Regla de seguridad: los secretos nunca se aceptan como argumentos, y el error
// tampoco los repite.
func TestSecretsAreRejectedAsArguments(t *testing.T) {
	uri := "otpauth://totp/a?secret=" + fakeBase32
	for _, args := range [][]string{
		{uri},
		{"add", uri},
		{"add", "--uri", uri},
		{"add", "--uri=" + uri},
		{"import-ga", uri},
		{"import-ga", "--uri=" + uri},
		{"init", uri},
		{"passwd", testPassword},
		{"init", "--password=" + testPassword},
		{"-" + fakeBase32},
	} {
		e := newEnv(t)
		e.piped = true
		out, err := e.run(nil, nil, args...)
		if err == nil {
			t.Errorf("%v: no hubo error", args)
			continue
		}
		shouldNotContain(t, out+err.Error(), fakeBase32, testPassword)
		if len(e.console.prompts) != 0 {
			t.Errorf("%v: preguntó %v", args, e.console.prompts)
		}
	}
}

func TestAddWithHiddenURI(t *testing.T) {
	e := newEnv(t)
	e.init()
	out := e.mustRun([]string{totpURI("GitHub", "usuario", rfcBase32), testPassword}, nil, "add")
	shouldContain(t, out, "GitHub:usuario")
	shouldNotContain(t, out, rfcBase32)
	shouldContain(t, e.list(), "GitHub:usuario", "1 cuenta")
}

func TestAddWithPipedURI(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.piped = true
	e.stdin = totpURI("GitHub", "usuario", rfcBase32) + "\r\n"
	e.mustRun([]string{testPassword}, nil, "add")
	shouldContain(t, e.list(), "GitHub:usuario")
}

func TestAddManually(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.mustRun([]string{"", "gezd gnbv gy3t qojq gezd gnbv gy3t qojq", testPassword}, []string{"GitHub", "usuario"}, "add")
	shouldContain(t, e.mustRun([]string{testPassword}, nil, "code", "github"), "287082")
}

func TestAddRejectsInvalidInputBeforeAskingPassword(t *testing.T) {
	e := newEnv(t)
	e.init()
	for _, uri := range []string{
		"otpauth://totp/a?secret=" + fakeBase32 + "!",
		"otpauth://hotp/a?secret=" + fakeBase32,
		"no es una uri " + fakeBase32,
	} {
		out, err := e.run([]string{uri}, nil, "add")
		if err == nil {
			t.Errorf("%s: no hubo error", uri)
			continue
		}
		shouldNotContain(t, out+err.Error(), fakeBase32)
		if len(e.console.prompts) != 1 {
			t.Errorf("preguntó %v", e.console.prompts)
		}
	}
}

func TestAddDuplicateAndConflict(t *testing.T) {
	e := newEnv(t)
	e.init()
	uri := totpURI("GitHub", "usuario", rfcBase32)
	e.add(uri)

	shouldContain(t, e.mustRun([]string{uri, testPassword}, nil, "add"), "ya existe")
	shouldContain(t, e.list(), "1 cuenta")

	other := totpURI("GitHub", "otro", rfcBase32)
	shouldContain(t, e.mustRun([]string{other, testPassword}, []string{"n"}, "add"), "Cancelado")
	shouldContain(t, e.list(), "1 cuenta")

	e.mustRun([]string{other, testPassword}, []string{"s"}, "add")
	shouldContain(t, e.list(), "2 cuentas")
}

func TestListSortsFiltersAndHidesSecrets(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.add(totpURI("Zeta", "a", "GEZDGNBV"))
	e.add(totpURI("alfa", "b", "MFRGGZDF"))
	e.add(totpURI("Beta", "c", fakeBase32))

	out := e.list()
	if !(strings.Index(out, "alfa:b") < strings.Index(out, "Beta:c") && strings.Index(out, "Beta:c") < strings.Index(out, "Zeta:a")) {
		t.Errorf("orden incorrecto:\n%s", out)
	}
	shouldNotContain(t, out, "GEZDGNBV", "MFRGGZDF", fakeBase32)

	filtered := e.mustRun([]string{testPassword}, nil, "list", "beta")
	shouldContain(t, filtered, "Beta:c", "1 cuenta")
	shouldNotContain(t, filtered, "Zeta")
}

func TestCodeShowsRFCValue(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.add("otpauth://totp/rfc?secret=" + rfcBase32 + "&digits=8")

	out := e.mustRun([]string{testPassword}, nil, "code", "rfc")
	shouldContain(t, out, "94287082", "quedan 1 s")
}

func TestCodeResolvesAmbiguity(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.add(totpURI("GitHub", "personal", rfcBase32))
	e.add(totpURI("GitHub", "trabajo", "GEZDGNBV"))
	e.add(totpURI("GitHub Enterprise", "personal", "MFRGGZDF"))

	t.Run("varias coincidencias", func(t *testing.T) {
		out, err := e.run([]string{testPassword}, nil, "code", "git")
		if err == nil {
			t.Error("no hubo error")
		}
		shouldContain(t, out, "GitHub:personal", "GitHub:trabajo", "GitHub Enterprise:personal", "ID ")
		shouldNotContain(t, out, "quedan")
	})

	t.Run("sin coincidencias", func(t *testing.T) {
		if _, err := e.run([]string{testPassword}, nil, "code", "nada"); err == nil {
			t.Error("no hubo error")
		}
	})

	t.Run("etiqueta exacta", func(t *testing.T) {
		shouldContain(t, e.mustRun([]string{testPassword}, nil, "code", "github:TRABAJO"), "GitHub:trabajo", "quedan")
	})

	t.Run("nombre exacto único", func(t *testing.T) {
		shouldContain(t, e.mustRun([]string{testPassword}, nil, "code", "trabajo"), "GitHub:trabajo", "quedan")
	})

	t.Run("por ID", func(t *testing.T) {
		out, _ := e.run([]string{testPassword}, nil, "code", "personal")
		line := out[strings.Index(out, "GitHub:personal"):]
		line = line[:strings.Index(line, "\n")]
		id := strings.TrimSuffix(line[strings.Index(line, "ID ")+3:], ")")
		shouldContain(t, e.mustRun([]string{testPassword}, nil, "code", id), "GitHub:personal", "quedan")
	})
}

func TestCodeArguments(t *testing.T) {
	e := newEnv(t)
	e.init()
	for _, args := range [][]string{
		{"code"},
		{"code", "a", "b"},
		{"code", "--all", "a"},
		{"code", "--all", "--copy"},
	} {
		if _, err := e.run(nil, nil, args...); err == nil {
			t.Errorf("%v: no hubo error", args)
		}
	}
}

func TestCodeAll(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.add("otpauth://totp/Rfc:a?secret=" + rfcBase32 + "&digits=8")
	e.add(totpURI("Otra", "b", "GEZDGNBV"))

	out := e.mustRun([]string{testPassword}, nil, "code", "--all")
	shouldContain(t, out, "Rfc:a", "94287082", "Otra:b", "1 s")
	shouldNotContain(t, out, rfcBase32)
}

func TestCodeCopyClearsClipboardAtExpiry(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.add("otpauth://totp/rfc?secret=" + rfcBase32 + "&digits=8")

	e.mustRun([]string{testPassword}, nil, "code", "rfc", "--copy")
	if len(e.clipboard.writes) != 2 || e.clipboard.writes[0] != "94287082" || e.clipboard.writes[1] != "" {
		t.Errorf("escrituras = %q", e.clipboard.writes)
	}
	if e.slept != time.Second {
		t.Errorf("esperó %v, se esperaba 1 s", e.slept)
	}
}

func TestCodeCopyKeepsWhatUserCopiedLater(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.add("otpauth://totp/rfc?secret=" + rfcBase32)
	e.clipboard.onSleep = "algo que copió el usuario"

	e.mustRun([]string{testPassword}, nil, "code", "rfc", "--copy")
	if e.clipboard.content != "algo que copió el usuario" {
		t.Errorf("portapapeles = %q", e.clipboard.content)
	}
}

func TestCodeDoesNotTouchClipboardByDefault(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.add("otpauth://totp/rfc?secret=" + rfcBase32)
	e.mustRun([]string{testPassword}, nil, "code", "rfc")
	if len(e.clipboard.writes) != 0 {
		t.Errorf("escrituras = %q", e.clipboard.writes)
	}
}

func TestRemove(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.add(totpURI("GitHub", "uno", rfcBase32))
	e.add(totpURI("GitHub", "dos", "GEZDGNBV"))

	if _, err := e.run([]string{testPassword}, nil, "rm", "github"); err == nil {
		t.Error("varias coincidencias: no hubo error")
	}
	shouldContain(t, e.list(), "2 cuentas")

	shouldContain(t, e.mustRun([]string{testPassword}, []string{"n"}, "rm", "uno"), "Cancelado")
	shouldContain(t, e.list(), "2 cuentas")

	shouldContain(t, e.mustRun([]string{testPassword}, []string{""}, "rm", "uno"), "Cancelado")
	shouldContain(t, e.list(), "2 cuentas")

	shouldContain(t, e.mustRun([]string{testPassword}, []string{"sí"}, "rm", "uno"), "eliminada")
	out := e.list()
	shouldContain(t, out, "1 cuenta", "GitHub:dos")
	shouldNotContain(t, out, "GitHub:uno")
}

func TestImportWithHiddenInput(t *testing.T) {
	e := newEnv(t)
	e.init()
	first := migrationURI(7, 0, 2, ga("a", "E"), ga("b", "E"))
	second := migrationURI(7, 1, 2, ga("c", "E"))

	out := e.mustRun([]string{first, second, "", testPassword}, []string{"s"}, "import-ga")
	shouldContain(t, out, "Recibidas: 3", "Nuevas: 3", "2 de 2 QR", "3 cuentas importadas")
	shouldContain(t, e.list(), "E:a", "E:b", "E:c", "3 cuentas")
}

func TestImportWithPipedInput(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.piped = true
	e.stdin = migrationURI(7, 0, 1, ga("a", "E")) + "\r\n\r\n"
	e.mustRun([]string{testPassword}, []string{"s"}, "import-ga")
	shouldContain(t, e.list(), "E:a")
}

func TestImportFromFile(t *testing.T) {
	uri := migrationURI(7, 0, 1, ga("a", "E"))
	write := func(t *testing.T, content []byte) string {
		path := filepath.Join(t.TempDir(), "uris.txt")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("UTF-8", func(t *testing.T) {
		e := newEnv(t)
		e.init()
		path := write(t, []byte(uri+"\n"))
		out := e.mustRun([]string{testPassword}, []string{"s"}, "import-ga", "--file", path)
		shouldContain(t, out, "Recuerda borrar", path)
		shouldContain(t, e.list(), "E:a")
	})

	t.Run("UTF-8 con BOM", func(t *testing.T) {
		e := newEnv(t)
		e.init()
		path := write(t, append([]byte{0xef, 0xbb, 0xbf}, uri...))
		e.mustRun([]string{testPassword}, []string{"s"}, "import-ga", "--file", path)
		shouldContain(t, e.list(), "E:a")
	})

	t.Run("UTF-16", func(t *testing.T) {
		e := newEnv(t)
		e.init()
		_, err := e.run(nil, nil, "import-ga", "--file", write(t, []byte{0xff, 0xfe, 'o', 0}))
		if err == nil || !strings.Contains(err.Error(), "UTF-16") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("recuerda borrarlo aunque se cancele", func(t *testing.T) {
		e := newEnv(t)
		e.init()
		out := e.mustRun([]string{testPassword}, []string{"n"}, "import-ga", "--file", write(t, []byte(uri)))
		shouldContain(t, out, "Cancelado", "Recuerda borrar")
		shouldContain(t, e.list(), "0 cuentas")
	})

	t.Run("no existe", func(t *testing.T) {
		e := newEnv(t)
		e.init()
		if _, err := e.run(nil, nil, "import-ga", "--file", "no-existe.txt"); err == nil {
			t.Error("no hubo error")
		}
	})
}

func TestImportWithoutURIs(t *testing.T) {
	e := newEnv(t)
	e.init()
	if _, err := e.run([]string{""}, nil, "import-ga"); err == nil {
		t.Error("no hubo error")
	}
}

func TestImportCancelSavesNothing(t *testing.T) {
	e := newEnv(t)
	e.init()
	before, _ := os.ReadFile(e.path)
	out := e.mustRun([]string{migrationURI(7, 0, 1, ga("a", "E")), "", testPassword}, []string{"n"}, "import-ga")
	shouldContain(t, out, "Cancelado")
	if after, _ := os.ReadFile(e.path); !bytes.Equal(before, after) {
		t.Error("el vault cambió")
	}
}

func TestImportReportsProblemsAndKeepsGoing(t *testing.T) {
	e := newEnv(t)
	e.init()
	hotp := gaAccount{name: "contador", issuer: "E", secret: []byte("secreto-falso-h"), otpType: 1}
	uris := []string{
		migrationURI(7, 0, 3, ga("a", "E"), hotp),
		"esto-no-es-una-uri-" + fakeBase32,
		migrationURI(7, 0, 3, ga("a", "E")),
	}

	out := e.mustRun([]string{uris[0], uris[1], uris[2], "", testPassword}, []string{"s"}, "import-ga")
	shouldContain(t, out,
		"Recibidas: 3", "Nuevas: 1", "Ya presentes: 1", "Rechazadas: 1",
		"Faltan los QR: 2, 3",
		"Leídos más de una vez: 1",
		"URI 2 no válida",
		"Rechazada E:contador",
		"incompleta",
	)
	shouldNotContain(t, out, fakeBase32)
	shouldContain(t, e.list(), "1 cuenta")
}

func TestImportInPartsAddsOnlyWhatIsNew(t *testing.T) {
	e := newEnv(t)
	e.init()
	first := migrationURI(7, 0, 2, ga("a", "E"))
	second := migrationURI(7, 1, 2, ga("b", "E"))

	e.mustRun([]string{first, "", testPassword}, []string{"s"}, "import-ga")
	out := e.mustRun([]string{first, second, "", testPassword}, []string{"s"}, "import-ga")
	shouldContain(t, out, "Nuevas: 1", "Ya presentes: 1")
	shouldContain(t, e.list(), "2 cuentas")

	before, _ := os.ReadFile(e.path)
	out = e.mustRun([]string{first, second, "", testPassword}, nil, "import-ga")
	shouldContain(t, out, "No hay cuentas nuevas")
	if after, _ := os.ReadFile(e.path); !bytes.Equal(before, after) {
		t.Error("guardó sin cambios")
	}
}

func TestImportAsksAboutConflicts(t *testing.T) {
	secret := []byte("secreto-falso-compartido")
	account := func(name string) gaAccount { return gaAccount{name: name, issuer: "E", secret: secret} }

	t.Run("rechazado", func(t *testing.T) {
		e := newEnv(t)
		e.init()
		out := e.mustRun([]string{migrationURI(7, 0, 1, account("a"), account("b")), "", testPassword}, []string{"s", "n"}, "import-ga")
		shouldContain(t, out, "Conflictos: 1", "1 cuenta importada")
		shouldContain(t, e.list(), "1 cuenta")
	})

	t.Run("aceptado", func(t *testing.T) {
		e := newEnv(t)
		e.init()
		e.mustRun([]string{migrationURI(7, 0, 1, account("a"), account("b")), "", testPassword}, []string{"s", "s"}, "import-ga")
		shouldContain(t, e.list(), "2 cuentas")
	})

	t.Run("solo un conflicto rechazado no guarda", func(t *testing.T) {
		e := newEnv(t)
		e.init()
		e.mustRun([]string{migrationURI(7, 0, 1, account("a")), "", testPassword}, []string{"s"}, "import-ga")
		before, _ := os.ReadFile(e.path)
		out := e.mustRun([]string{migrationURI(7, 0, 1, account("b")), "", testPassword}, []string{"s", "n"}, "import-ga")
		shouldContain(t, out, "No se importó ninguna")
		if after, _ := os.ReadFile(e.path); !bytes.Equal(before, after) {
			t.Error("guardó sin cambios")
		}
	})
}

func TestPasswd(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.add(totpURI("GitHub", "usuario", rfcBase32))

	out := e.mustRun([]string{testPassword, otherPassword, otherPassword}, nil, "passwd")
	shouldContain(t, out, "Contraseña cambiada", "respaldos exportados")

	if _, err := e.run([]string{testPassword}, nil, "list"); !errors.Is(err, vault.ErrInvalid) {
		t.Errorf("la contraseña anterior: err = %v", err)
	}
	shouldContain(t, e.mustRun([]string{otherPassword}, nil, "list"), "GitHub:usuario")

	// El .bak tampoco abre ya con la anterior.
	restored := newEnv(t)
	if _, err := restored.run([]string{testPassword}, nil, "restore", e.path+".bak"); !errors.Is(err, vault.ErrInvalid) {
		t.Errorf("el .bak con la contraseña anterior: err = %v", err)
	}
	restored.mustRun([]string{otherPassword}, nil, "restore", e.path+".bak")
}

func TestPasswdRejectsBadInput(t *testing.T) {
	e := newEnv(t)
	e.init()
	before, _ := os.ReadFile(e.path)
	if _, err := e.run([]string{otherPassword, otherPassword, otherPassword}, nil, "passwd"); !errors.Is(err, vault.ErrInvalid) {
		t.Errorf("contraseña actual incorrecta: err = %v", err)
	}
	if _, err := e.run([]string{testPassword, "corta"}, nil, "passwd"); err == nil {
		t.Error("contraseña nueva corta: no hubo error")
	}
	if _, err := e.run([]string{testPassword, otherPassword, "distinta-de-la-otra"}, nil, "passwd"); err == nil {
		t.Error("contraseñas distintas: no hubo error")
	}
	if after, _ := os.ReadFile(e.path); !bytes.Equal(before, after) {
		t.Error("el vault cambió")
	}
}

// Criterio de aceptación: exportar y restaurar recupera todas las entradas.
func TestExportRestoreRoundTrip(t *testing.T) {
	source := newEnv(t)
	source.init()
	source.add("otpauth://totp/Rfc:a?secret=" + rfcBase32 + "&digits=8")
	source.add(totpURI("Otra", "b", fakeBase32))
	wantCodes := source.mustRun([]string{testPassword}, nil, "code", "--all")

	backup := filepath.Join(t.TempDir(), "respaldo.piko")
	out := source.mustRun([]string{testPassword}, nil, "export", "--encrypted", backup)
	shouldContain(t, out, "Respaldo cifrado", backup)

	content, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(content, []byte("Rfc")) || bytes.Contains(content, []byte("otpauth")) {
		t.Error("el respaldo contiene datos en claro")
	}

	target := newEnv(t)
	out = target.mustRun([]string{testPassword}, nil, "restore", backup)
	shouldContain(t, out, "2 cuentas restauradas")
	if got := target.mustRun([]string{testPassword}, nil, "code", "--all"); got != wantCodes {
		t.Errorf("códigos tras restaurar:\n%s\nse esperaban:\n%s", got, wantCodes)
	}
}

func TestRestoreOverExistingVault(t *testing.T) {
	source := newEnv(t)
	source.init()
	source.add(totpURI("Respaldo", "a", rfcBase32))
	backup := filepath.Join(t.TempDir(), "respaldo.piko")
	source.mustRun([]string{testPassword}, nil, "export", "--encrypted", backup)

	e := newEnv(t)
	e.mustRun([]string{otherPassword, otherPassword}, nil, "init")
	e.mustRun([]string{totpURI("Actual", "b", fakeBase32), otherPassword}, nil, "add")
	before, _ := os.ReadFile(e.path)

	shouldContain(t, e.mustRun([]string{testPassword}, []string{"n"}, "restore", backup), "Cancelado")
	if after, _ := os.ReadFile(e.path); !bytes.Equal(before, after) {
		t.Error("cancelar cambió el vault")
	}

	out := e.mustRun([]string{testPassword}, []string{"s"}, "restore", backup)
	shouldContain(t, out, "1 cuenta restaurada", "pre-restore", "contraseña del respaldo")
	shouldContain(t, e.list(), "Respaldo:a")

	saved, err := filepath.Glob(e.path + ".pre-restore-*")
	if err != nil || len(saved) != 1 {
		t.Fatalf("copias = %v, err = %v", saved, err)
	}
	if content, _ := os.ReadFile(saved[0]); !bytes.Equal(content, before) {
		t.Error("la copia no es el vault reemplazado")
	}
}

func TestRestoreRejectsBadFiles(t *testing.T) {
	e := newEnv(t)
	bad := filepath.Join(t.TempDir(), "malo.bin")
	if err := os.WriteFile(bad, []byte("esto no es un vault"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.run([]string{testPassword}, nil, "restore", bad); !errors.Is(err, vault.ErrInvalid) {
		t.Errorf("err = %v", err)
	}
	if _, err := os.Stat(e.path); err == nil {
		t.Error("se creó el vault")
	}
}

func TestExportEncryptedRefusesOverwrite(t *testing.T) {
	e := newEnv(t)
	e.init()
	dest := filepath.Join(t.TempDir(), "existente")
	if err := os.WriteFile(dest, []byte("no pisar"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.run([]string{testPassword}, nil, "export", "--encrypted", dest); !errors.Is(err, vault.ErrExists) {
		t.Errorf("err = %v", err)
	}
}

func TestExportArguments(t *testing.T) {
	e := newEnv(t)
	e.init()
	for _, args := range [][]string{
		{"export"},
		{"export", "--encrypted", "a", "--plaintext", "b"},
	} {
		if _, err := e.run(nil, nil, args...); err == nil {
			t.Errorf("%v: no hubo error", args)
		}
	}
}

func TestExportPlaintext(t *testing.T) {
	e := newEnv(t)
	e.init()
	e.add(totpURI("GitHub", "usuario", rfcBase32))
	dest := filepath.Join(t.TempDir(), "claves.txt")

	t.Run("exige escribir la confirmación exacta", func(t *testing.T) {
		for _, answer := range []string{"", "s", "sí", "exportar"} {
			out := e.mustRun([]string{testPassword}, []string{answer}, "export", "--plaintext", dest)
			shouldContain(t, out, "Cancelado")
			if _, err := os.Stat(dest); err == nil {
				t.Fatalf("%q creó el archivo", answer)
			}
		}
	})

	t.Run("exporta URIs que se pueden volver a leer", func(t *testing.T) {
		out := e.mustRun([]string{testPassword}, []string{"EXPORTAR"}, "export", "--plaintext", dest)
		shouldContain(t, out, "1 cuenta exportada en claro")
		shouldNotContain(t, out, rfcBase32)

		content, err := os.ReadFile(dest)
		if err != nil {
			t.Fatal(err)
		}
		shouldContain(t, string(content), "otpauth://totp/GitHub:usuario", rfcBase32)

		other := newEnv(t)
		other.init()
		other.add(strings.TrimSpace(string(content)))
		shouldContain(t, other.list(), "GitHub:usuario")
	})

	t.Run("no reemplaza un archivo existente", func(t *testing.T) {
		_, err := e.run([]string{testPassword}, []string{"EXPORTAR"}, "export", "--plaintext", dest)
		if !errors.Is(err, vault.ErrExists) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestPasswordsAreZeroedAfterUse(t *testing.T) {
	e := newEnv(t)
	dest := filepath.Join(t.TempDir(), "respaldo")
	backupEnv := newEnv(t)

	check := func(name string) {
		t.Helper()
		for _, secret := range e.console.given {
			if !bytes.Equal(secret, make([]byte, len(secret))) {
				t.Errorf("%s: quedó sin poner a cero una entrada de %d bytes", name, len(secret))
			}
		}
	}

	e.mustRun([]string{testPassword, testPassword}, nil, "init")
	check("init")
	e.mustRun([]string{totpURI("G", "u", rfcBase32), testPassword}, nil, "add")
	check("add")
	e.mustRun([]string{testPassword}, nil, "list")
	check("list")
	e.mustRun([]string{testPassword}, nil, "code", "u")
	check("code")
	e.mustRun([]string{migrationURI(7, 0, 1, ga("a", "E")), "", testPassword}, []string{"s"}, "import-ga")
	check("import-ga")
	e.mustRun([]string{testPassword}, []string{"s"}, "rm", "a")
	check("rm")
	e.mustRun([]string{testPassword}, nil, "export", "--encrypted", dest)
	check("export")
	e.mustRun([]string{testPassword, otherPassword, otherPassword}, nil, "passwd")
	check("passwd")

	backupEnv.mustRun([]string{testPassword}, nil, "restore", dest)
	for _, secret := range backupEnv.console.given {
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Error("restore: la contraseña quedó sin poner a cero")
		}
	}
}

func TestHelpWorksWithoutTerminal(t *testing.T) {
	e := newEnv(t)
	out := e.mustRun(nil, nil, "--help")
	shouldContain(t, out, "init", "add", "list", "code", "rm", "import-ga", "passwd", "export", "restore")
}
