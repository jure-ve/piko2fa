package vault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"piko2fa/internal/model"
	"piko2fa/internal/totp"
)

// Contraseñas y secretos de estos tests son falsos.
var (
	testPassword  = []byte("contraseña-falsa-de-prueba")
	otherPassword = []byte("otra-contraseña-falsa")
	testParams    = kdfParams{time: minTime, memoryKiB: minMemoryKiB, threads: minThreads}
)

func vaultPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "vault.bin")
}

func openTest(t *testing.T, path string) *FileStore {
	t.Helper()
	s, err := open(path, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s.params = testParams
	t.Cleanup(func() { s.Close() })
	return s
}

func newEntry(t *testing.T, name, issuer string) model.Entry {
	t.Helper()
	e, err := model.New(name, issuer, []byte("secreto-falso-"+name), totp.SHA1, 6, 30)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// initVault crea en path un vault con las cuentas indicadas y lo cierra.
func initVault(t *testing.T, path string, names ...string) {
	t.Helper()
	s := openTest(t, path)
	if err := s.Init(testPassword); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if err := s.Add(newEntry(t, name, "Emisor")); err != nil {
			t.Fatal(err)
		}
	}
	if len(names) > 0 {
		if err := s.Save(testPassword); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// names abre path y devuelve los nombres de sus cuentas, ordenados.
func names(t *testing.T, path string) []string {
	t.Helper()
	s := openTest(t, path)
	defer s.Close()
	if err := s.Load(testPassword); err != nil {
		t.Fatalf("el vault no abre: %v", err)
	}
	var out []string
	for _, e := range s.List() {
		out = append(out, e.Name)
	}
	slices.Sort(out)
	return out
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// loadShouldFail comprueba que el archivo no abre y que no hay datos parciales.
func loadShouldFail(t *testing.T, path string, want error) {
	t.Helper()
	s := openTest(t, path)
	defer s.Close()
	err := s.Load(testPassword)
	if !errors.Is(err, want) {
		t.Errorf("Load: err = %v, se esperaba %v", err, want)
	}
	if got := s.List(); len(got) != 0 {
		t.Errorf("hay %d cuentas tras un Load fallido", len(got))
	}
	if err := s.Save(testPassword); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("Save tras un Load fallido: err = %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	path := vaultPath(t)
	s := openTest(t, path)
	if err := s.Init(testPassword); err != nil {
		t.Fatal(err)
	}

	want, err := model.New("usuario@example.com", "GitHub", []byte("Hello!\xde\xad\xbe\xef"), totp.SHA256, 8, 60)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(want); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(newEntry(t, "otra", "Emisor")); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(testPassword); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s = openTest(t, path)
	if err := s.Load(testPassword); err != nil {
		t.Fatal(err)
	}
	if n := len(s.List()); n != 2 {
		t.Fatalf("cuentas = %d, se esperaban 2", n)
	}
	got, err := s.Get(want.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.Name != want.Name || got.Issuer != want.Issuer ||
		!bytes.Equal(got.Secret, want.Secret) || got.Algorithm != want.Algorithm ||
		got.Digits != want.Digits || got.Period != want.Period || got.Type != want.Type ||
		!got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("la cuenta cambió: %v, se esperaba %v", got, want)
	}
}

func TestFileHidesContents(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "nombre-visible")

	data := readFile(t, path)
	for _, text := range []string{"nombre-visible", "Emisor", "secreto-falso", "schema", "entries", "c2VjcmV0by1mYWxzby"} {
		if bytes.Contains(data, []byte(text)) {
			t.Errorf("el archivo contiene %q en claro", text)
		}
	}
}

func TestInit(t *testing.T) {
	t.Run("no reemplaza un vault existente", func(t *testing.T) {
		path := vaultPath(t)
		initVault(t, path, "a")
		before := readFile(t, path)

		s := openTest(t, path)
		if err := s.Init(testPassword); !errors.Is(err, ErrExists) {
			t.Errorf("err = %v, se esperaba ErrExists", err)
		}
		if !bytes.Equal(readFile(t, path), before) {
			t.Error("el archivo cambió")
		}
	})

	t.Run("contraseña vacía", func(t *testing.T) {
		s := openTest(t, vaultPath(t))
		if err := s.Init(nil); !errors.Is(err, ErrEmptyPassword) {
			t.Errorf("err = %v, se esperaba ErrEmptyPassword", err)
		}
	})
}

func TestLoadMissingVault(t *testing.T) {
	s := openTest(t, vaultPath(t))
	if err := s.Load(testPassword); !errors.Is(err, ErrNoVault) {
		t.Errorf("err = %v, se esperaba ErrNoVault", err)
	}
}

func TestLoadWrongPassword(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")

	s := openTest(t, path)
	if err := s.Load(otherPassword); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, se esperaba ErrInvalid", err)
	}
	if len(s.List()) != 0 {
		t.Error("hay cuentas tras un Load fallido")
	}
}

func TestFailedReloadKeepsEntries(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")

	s := openTest(t, path)
	if err := s.Load(testPassword); err != nil {
		t.Fatal(err)
	}
	if err := s.Load(otherPassword); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, se esperaba ErrInvalid", err)
	}
	if len(s.List()) != 1 || len(s.List()[0].Secret) == 0 || s.List()[0].Secret[0] == 0 {
		t.Error("el Load fallido alteró las cuentas en memoria")
	}
}

func TestLoadTruncatedFile(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path)
	data := readFile(t, path)

	for n := range len(data) {
		writeFile(t, path, data[:n])
		loadShouldFail(t, path, ErrInvalid)
	}
}

func TestLoadTrailingData(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path)
	writeFile(t, path, append(readFile(t, path), 0))
	loadShouldFail(t, path, ErrInvalid)
}

// Criterio de aceptación: un bit alterado en cualquier zona impide abrir.
func TestLoadBitFlipInEveryByte(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path)
	data := readFile(t, path)
	versionOffset := len(magic)

	for i := range data {
		flipped := bytes.Clone(data)
		flipped[i] ^= 0x01
		writeFile(t, path, flipped)

		want := ErrInvalid
		if i == versionOffset {
			want = ErrUnsupportedVersion
		}
		loadShouldFail(t, path, want)
	}
}

// Sin los límites, estos parámetros harían entrar en pánico a argon2 o pedirían
// cantidades enormes de memoria antes de poder autenticar la cabecera.
func TestLoadRejectsParamsOutOfBounds(t *testing.T) {
	const timeOffset, memoryOffset, threadsOffset = 5, 9, 13

	tests := []struct {
		name  string
		apply func([]byte)
	}{
		{"tiempo cero", func(d []byte) { binary.BigEndian.PutUint32(d[timeOffset:], 0) }},
		{"tiempo enorme", func(d []byte) { binary.BigEndian.PutUint32(d[timeOffset:], 0xffffffff) }},
		{"tiempo justo sobre el límite", func(d []byte) { binary.BigEndian.PutUint32(d[timeOffset:], maxTime+1) }},
		{"memoria cero", func(d []byte) { binary.BigEndian.PutUint32(d[memoryOffset:], 0) }},
		{"memoria enorme", func(d []byte) { binary.BigEndian.PutUint32(d[memoryOffset:], 0xffffffff) }},
		{"memoria con el bit alto alterado", func(d []byte) { d[memoryOffset] ^= 0x80 }},
		{"memoria justo bajo el límite", func(d []byte) { binary.BigEndian.PutUint32(d[memoryOffset:], minMemoryKiB-1) }},
		{"memoria justo sobre el límite", func(d []byte) { binary.BigEndian.PutUint32(d[memoryOffset:], maxMemoryKiB+1) }},
		{"hilos cero", func(d []byte) { d[threadsOffset] = 0 }},
		{"hilos enormes", func(d []byte) { d[threadsOffset] = 0xff }},
		{"hilos justo sobre el límite", func(d []byte) { d[threadsOffset] = maxThreads + 1 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := vaultPath(t)
			initVault(t, path)
			data := readFile(t, path)
			tt.apply(data)
			writeFile(t, path, data)

			start := time.Now()
			loadShouldFail(t, path, ErrInvalid)
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Errorf("tardó %v: parece que derivó la clave", elapsed)
			}
		})
	}
}

func TestLoadUnknownFormatVersion(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path)
	data := readFile(t, path)
	data[len(magic)] = formatVersion + 1
	writeFile(t, path, data)
	loadShouldFail(t, path, ErrUnsupportedVersion)

	// Una versión futura puede tener otra longitud de cabecera.
	writeFile(t, path, data[:len(magic)+1])
	loadShouldFail(t, path, ErrUnsupportedVersion)
}

func TestLoadRejectsBadMagic(t *testing.T) {
	path := vaultPath(t)
	writeFile(t, path, bytes.Repeat([]byte("x"), 200))
	loadShouldFail(t, path, ErrInvalid)
}

// Contenido correctamente cifrado pero no válido: tampoco debe abrir a medias.
func TestLoadRejectsInvalidContents(t *testing.T) {
	validEntry := `{"id":"1","name":"buena","issuer":"E","secret":"AQID","algorithm":"SHA1","digits":6,"period":30,"type":"totp"}`
	badEntry := `{"id":"2","name":"mala","issuer":"E","secret":"AQID","algorithm":"MD5","digits":6,"period":30,"type":"totp"}`

	tests := []struct {
		name, plaintext string
		want            error
	}{
		{"no es JSON", "esto no es JSON", ErrInvalid},
		{"esquema futuro", `{"schema":2,"entries":[]}`, ErrUnsupportedVersion},
		{"sin esquema", `{"entries":[]}`, ErrUnsupportedVersion},
		{"una cuenta inválida entre válidas", `{"schema":1,"entries":[` + validEntry + `,` + badEntry + `]}`, ErrInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := seal(testPassword, testParams, []byte(tt.plaintext))
			if err != nil {
				t.Fatal(err)
			}
			path := vaultPath(t)
			writeFile(t, path, data)
			loadShouldFail(t, path, tt.want)
		})
	}
}

func TestEachSaveUsesNewSaltAndNonce(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path)

	s := openTest(t, path)
	if err := s.Load(testPassword); err != nil {
		t.Fatal(err)
	}

	type randoms struct{ salt, nonce string }
	seen := map[randoms]bool{}
	for range 4 {
		if err := s.Save(testPassword); err != nil {
			t.Fatal(err)
		}
		data := readFile(t, path)
		r := randoms{
			salt:  string(data[headerSize-saltSize : headerSize]),
			nonce: string(data[headerSize : minSize-16]),
		}
		for other := range seen {
			if other.salt == r.salt {
				t.Error("sal repetida")
			}
			if other.nonce == r.nonce {
				t.Error("nonce repetido")
			}
		}
		seen[r] = true
	}
}

func TestDefaultParamsAreStoredAndWithinBounds(t *testing.T) {
	if !defaultParams.valid() {
		t.Fatal("los parámetros por defecto están fuera de los límites")
	}
	if defaultParams.time != 3 || defaultParams.memoryKiB != 64*1024 || defaultParams.threads != 4 {
		t.Errorf("parámetros por defecto = %+v", defaultParams)
	}

	data, err := seal(testPassword, defaultParams, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(data[9:]); got != defaultParams.memoryKiB {
		t.Errorf("memoria en la cabecera = %d", got)
	}
	plaintext, err := unseal(testPassword, data)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "{}" {
		t.Errorf("texto descifrado = %q", plaintext)
	}
}

func TestOpenUsesDefaultParams(t *testing.T) {
	s, err := Open(vaultPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.params != defaultParams {
		t.Errorf("params = %+v", s.params)
	}
}

func TestSaveRequiresLoadedVault(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")
	before := readFile(t, path)

	// Sin esta protección, un Save pisaría el vault con uno vacío.
	s := openTest(t, path)
	if err := s.Save(testPassword); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("Save: err = %v, se esperaba ErrNotLoaded", err)
	}
	if err := s.Add(newEntry(t, "b", "E")); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("Add: err = %v, se esperaba ErrNotLoaded", err)
	}
	if err := s.Remove("x"); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("Remove: err = %v, se esperaba ErrNotLoaded", err)
	}
	if !bytes.Equal(readFile(t, path), before) {
		t.Error("el archivo cambió")
	}
}

func TestSaveRejectsOtherPassword(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")

	s := openTest(t, path)
	if err := s.Load(testPassword); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(newEntry(t, "b", "E")); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, path)

	if err := s.Save(otherPassword); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, se esperaba ErrInvalid", err)
	}
	if !bytes.Equal(readFile(t, path), before) {
		t.Error("el archivo cambió")
	}
	if err := s.Save(nil); !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("contraseña vacía: err = %v", err)
	}
}

func TestSaveKeepsPreviousVersionInBackup(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")
	previous := readFile(t, path)

	s := openTest(t, path)
	if err := s.Load(testPassword); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(newEntry(t, "b", "E")); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(testPassword); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(readFile(t, path+backupSuffix), previous) {
		t.Error("el .bak no es la versión anterior")
	}
	if got := names(t, path); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("cuentas = %v", got)
	}
}

// Un vault dañado no debe reemplazar a un respaldo que aún funciona.
func TestSaveDoesNotOverwriteBackupWithCorruptVault(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")

	s := openTest(t, path)
	if err := s.Load(testPassword); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(testPassword); err != nil {
		t.Fatal(err)
	}
	goodBackup := readFile(t, path+backupSuffix)

	corrupt := readFile(t, path)
	corrupt[len(corrupt)-1] ^= 0x01
	writeFile(t, path, corrupt)

	if err := s.Save(testPassword); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, se esperaba ErrInvalid", err)
	}
	if !bytes.Equal(readFile(t, path+backupSuffix), goodBackup) {
		t.Error("el vault dañado pisó el respaldo")
	}
	if !bytes.Equal(readFile(t, path), corrupt) {
		t.Error("el vault dañado cambió")
	}
}

func TestSaveWhenVaultWasDeleted(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")

	s := openTest(t, path)
	if err := s.Load(testPassword); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(testPassword); !errors.Is(err, ErrNoVault) {
		t.Errorf("err = %v, se esperaba ErrNoVault", err)
	}
}

// Criterio de aceptación: un fallo en cualquier paso deja un vault abrible.
func TestSaveFailureAtEveryStepKeepsVaultReadable(t *testing.T) {
	var steps []string
	for _, label := range []string{"backup", "vault"} {
		for _, step := range []string{"create", "write", "sync", "close", "rename", "syncdir"} {
			steps = append(steps, label+":"+step)
		}
	}

	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			path := vaultPath(t)
			initVault(t, path, "a")

			s := openTest(t, path)
			if err := s.Load(testPassword); err != nil {
				t.Fatal(err)
			}
			if err := s.Add(newEntry(t, "b", "E")); err != nil {
				t.Fatal(err)
			}

			injected := errors.New("fallo simulado")
			fired := false
			s.step = func(name string) error {
				if name == step {
					fired = true
					return injected
				}
				return nil
			}

			if err := s.Save(testPassword); !errors.Is(err, injected) {
				t.Errorf("Save: err = %v, se esperaba el fallo simulado", err)
			}
			if !fired {
				t.Fatal("el paso no se ejecutó")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}

			// El rename ya ocurrió si solo falló la sincronización posterior.
			want := []string{"a"}
			if step == "vault:syncdir" {
				want = []string{"a", "b"}
			}
			if got := names(t, path); !slices.Equal(got, want) {
				t.Errorf("cuentas = %v, se esperaban %v", got, want)
			}

			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".tmp") {
					t.Errorf("temporal sin limpiar: %s", e.Name())
				}
			}
		})
	}
}

func TestSaveCanRetryAfterFailure(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")

	s := openTest(t, path)
	if err := s.Load(testPassword); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(newEntry(t, "b", "E")); err != nil {
		t.Fatal(err)
	}
	s.step = func(name string) error {
		if name == "vault:write" {
			return errors.New("fallo simulado")
		}
		return nil
	}
	if err := s.Save(testPassword); err == nil {
		t.Fatal("no hubo error")
	}

	s.step = nil
	if err := s.Save(testPassword); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if got := names(t, path); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("cuentas = %v", got)
	}
}

func TestSaveLeavesOnlyExpectedFiles(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	slices.Sort(got)
	want := []string{"vault.bin", "vault.bin.bak", "vault.bin.lock"}
	if !slices.Equal(got, want) {
		t.Errorf("archivos = %v, se esperaban %v", got, want)
	}
}

// Windows no permite reemplazar un archivo abierto, como le ocurre a un
// antivirus que lo está analizando: el guardado debe reintentar.
func TestSaveRetriesRenameWhileFileIsOpenOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("solo aplica en Windows")
	}
	path := vaultPath(t)
	initVault(t, path, "a")

	s := openTest(t, path)
	if err := s.Load(testPassword); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(newEntry(t, "b", "E")); err != nil {
		t.Fatal(err)
	}

	var holder *os.File
	attempts := 0
	s.step = func(name string) error {
		if name != "vault:rename" {
			return nil
		}
		attempts++
		switch attempts {
		case 1:
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			holder = f
		case 3:
			holder.Close()
		}
		return nil
	}

	if err := s.Save(testPassword); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Errorf("intentos = %d, se esperaban 3", attempts)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if got := names(t, path); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("cuentas = %v", got)
	}
}

func TestLockExcludesSecondStore(t *testing.T) {
	path := vaultPath(t)
	first := openTest(t, path)

	if _, err := open(path, 100*time.Millisecond); !errors.Is(err, ErrLocked) {
		t.Errorf("err = %v, se esperaba ErrLocked", err)
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := open(path, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("tras Close: %v", err)
	}
	second.Close()
}

// Se ejecuta en un proceso aparte, lanzado por TestConcurrentProcessesLoseNoUpdates.
func TestHelperProcessAddEntry(t *testing.T) {
	path := os.Getenv("PIKO2FA_TEST_VAULT")
	if path == "" {
		t.Skip("solo se ejecuta como proceso auxiliar")
	}
	s := openTest(t, path)
	if err := s.Load(testPassword); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(newEntry(t, os.Getenv("PIKO2FA_TEST_NAME"), "E")); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(testPassword); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentProcessesLoseNoUpdates(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path)

	const processes = 6
	cmds := make([]*exec.Cmd, processes)
	outputs := make([]bytes.Buffer, processes)
	var want []string
	for i := range processes {
		name := fmt.Sprintf("proceso%d", i)
		want = append(want, name)
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcessAddEntry$", "-test.count=1")
		cmd.Env = append(os.Environ(), "PIKO2FA_TEST_VAULT="+path, "PIKO2FA_TEST_NAME="+name)
		cmd.Stdout = &outputs[i]
		cmd.Stderr = &outputs[i]
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds[i] = cmd
	}
	for i, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Errorf("proceso %d: %v\n%s", i, err, outputs[i].String())
		}
	}

	if got := names(t, path); !slices.Equal(got, want) {
		t.Errorf("cuentas = %v, se esperaban %v", got, want)
	}
}

func TestAddGetRemove(t *testing.T) {
	s := openTest(t, vaultPath(t))
	if err := s.Init(testPassword); err != nil {
		t.Fatal(err)
	}

	e := newEntry(t, "a", "E")
	if err := s.Add(e); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(e); !errors.Is(err, ErrDuplicateID) {
		t.Errorf("ID repetido: err = %v", err)
	}
	if err := s.Add(model.Entry{Name: "inválida"}); err == nil {
		t.Error("cuenta inválida: no hubo error")
	}
	noID := newEntry(t, "b", "E")
	noID.ID = ""
	if err := s.Add(noID); err == nil {
		t.Error("cuenta sin ID: no hubo error")
	}

	got, err := s.Get(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "a" {
		t.Errorf("Name = %q", got.Name)
	}
	if _, err := s.Get("no-existe"); !errors.Is(err, ErrEntryNotFound) {
		t.Errorf("Get: err = %v", err)
	}
	if err := s.Remove("no-existe"); !errors.Is(err, ErrEntryNotFound) {
		t.Errorf("Remove: err = %v", err)
	}

	if err := s.Remove(e.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(e.ID); !errors.Is(err, ErrEntryNotFound) {
		t.Errorf("tras Remove: err = %v", err)
	}
	if len(s.List()) != 0 {
		t.Error("la cuenta sigue en la lista")
	}
}

func TestAddKeepsItsOwnSecretCopy(t *testing.T) {
	s := openTest(t, vaultPath(t))
	if err := s.Init(testPassword); err != nil {
		t.Fatal(err)
	}

	e := newEntry(t, "a", "E")
	want := bytes.Clone(e.Secret)
	if err := s.Add(e); err != nil {
		t.Fatal(err)
	}
	clear(e.Secret)

	got, err := s.Get(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Secret, want) {
		t.Error("el almacén comparte el secreto con quien llamó a Add")
	}
}

func TestFind(t *testing.T) {
	s := openTest(t, vaultPath(t))
	if err := s.Init(testPassword); err != nil {
		t.Fatal(err)
	}
	for _, e := range []model.Entry{
		newEntry(t, "usuario@example.com", "GitHub"),
		newEntry(t, "otro@example.com", "GitLab"),
		newEntry(t, "Cuenta Ñandú", "Banco"),
	} {
		if err := s.Add(e); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		query string
		want  int
	}{
		{"", 3},
		{"github", 1},
		{"GIT", 2},
		{"example", 2},
		{"usuario", 1},
		{"ñandú", 1},
		{"nada", 0},
	}
	for _, tt := range tests {
		if got := s.Find(tt.query); len(got) != tt.want {
			t.Errorf("Find(%q) = %d cuentas, se esperaban %d", tt.query, len(got), tt.want)
		}
	}
}

func TestListCannotChangeStoreOrder(t *testing.T) {
	s := openTest(t, vaultPath(t))
	if err := s.Init(testPassword); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(newEntry(t, "a", "E")); err != nil {
		t.Fatal(err)
	}
	s.List()[0].Name = "cambiado"
	if s.List()[0].Name != "a" {
		t.Error("List expone el almacenamiento interno")
	}
}

func TestCloseZeroesSecrets(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")

	s := openTest(t, path)
	if err := s.Load(testPassword); err != nil {
		t.Fatal(err)
	}
	secret := s.List()[0].Secret
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Error("el secreto no quedó a cero")
	}
	if len(s.List()) != 0 {
		t.Error("quedan cuentas tras Close")
	}
}

func TestRemoveZeroesSecret(t *testing.T) {
	s := openTest(t, vaultPath(t))
	if err := s.Init(testPassword); err != nil {
		t.Fatal(err)
	}
	e := newEntry(t, "a", "E")
	if err := s.Add(e); err != nil {
		t.Fatal(err)
	}
	stored, err := s.Get(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(e.ID); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored.Secret, make([]byte, len(stored.Secret))) {
		t.Error("el secreto no quedó a cero")
	}
}

func TestClosedStoreRejectsOperations(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")
	s := openTest(t, path)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("segundo Close: %v", err)
	}

	for name, err := range map[string]error{
		"Init":   s.Init(testPassword),
		"Load":   s.Load(testPassword),
		"Save":   s.Save(testPassword),
		"Add":    s.Add(newEntry(t, "b", "E")),
		"Remove": s.Remove("x"),
	} {
		if !errors.Is(err, ErrClosed) {
			t.Errorf("%s: err = %v, se esperaba ErrClosed", name, err)
		}
	}
}

func TestPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows no aplica estos permisos")
	}
	path := filepath.Join(t.TempDir(), "nuevo", "vault.bin")
	initVault(t, path, "a")

	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("directorio: %o, se esperaba 700", perm)
	}
	for _, file := range []string{path, path + backupSuffix} {
		info, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s: %o, se esperaba 600", filepath.Base(file), perm)
		}
	}
}

func TestOpenCreatesDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "vault.bin")
	s := openTest(t, path)
	if err := s.Init(testPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error(err)
	}
}

func TestDefaultPath(t *testing.T) {
	path, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "vault.bin" || filepath.Base(filepath.Dir(path)) != "piko2fa" {
		t.Errorf("ruta inesperada: %s", path)
	}
	if runtime.GOOS == "windows" {
		local := os.Getenv("LocalAppData")
		if !strings.HasPrefix(path, local) {
			t.Errorf("%s no está dentro de %%LocalAppData%%", path)
		}
	}
}
