package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func loadsWith(t *testing.T, path string, password []byte) bool {
	t.Helper()
	data := readFile(t, path)
	plaintext, err := unseal(password, data)
	if err != nil {
		return false
	}
	clear(plaintext)
	return true
}

func TestChangePasswordCoversVaultAndBackup(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")

	s := openTest(t, path)
	if err := s.ChangePassword(testPassword, otherPassword); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{path, path + backupSuffix} {
		if loadsWith(t, file, testPassword) {
			t.Errorf("%s sigue abriendo con la contraseña anterior", filepath.Base(file))
		}
		if !loadsWith(t, file, otherPassword) {
			t.Errorf("%s no abre con la contraseña nueva", filepath.Base(file))
		}
	}
	if err := s.Load(otherPassword); err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 1 {
		t.Errorf("cuentas = %d, se esperaba 1", len(s.List()))
	}
}

func TestChangePasswordWithoutBackup(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path)

	s := openTest(t, path)
	if err := s.ChangePassword(testPassword, otherPassword); err != nil {
		t.Fatal(err)
	}
	if !loadsWith(t, path, otherPassword) {
		t.Error("el vault no abre con la contraseña nueva")
	}
	if _, err := os.Stat(path + backupSuffix); err == nil {
		t.Error("se creó un .bak que no existía")
	}
}

func TestChangePasswordRejectsBadInput(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")
	before := readFile(t, path)

	s := openTest(t, path)
	if err := s.ChangePassword(otherPassword, []byte("nueva-falsa")); !errors.Is(err, ErrInvalid) {
		t.Errorf("contraseña incorrecta: err = %v", err)
	}
	if err := s.ChangePassword(testPassword, nil); !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("contraseña vacía: err = %v", err)
	}
	if !bytes.Equal(readFile(t, path), before) {
		t.Error("el vault cambió")
	}
}

func TestChangePasswordRefusesUnreadableBackup(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")
	before := readFile(t, path)
	writeFile(t, path+backupSuffix, []byte("respaldo dañado"))

	s := openTest(t, path)
	if err := s.ChangePassword(testPassword, otherPassword); !errors.Is(err, ErrBackupUnreadable) {
		t.Errorf("err = %v, se esperaba ErrBackupUnreadable", err)
	}
	if !bytes.Equal(readFile(t, path), before) {
		t.Error("el vault cambió")
	}
	if got := readFile(t, path+backupSuffix); string(got) != "respaldo dañado" {
		t.Error("el .bak cambió: decidir qué hacer con él es del usuario")
	}
}

func TestChangePasswordFailureCanBeRetried(t *testing.T) {
	steps := []string{"backup:write", "backup:rename", "vault:create", "vault:write", "vault:rename"}

	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			path := vaultPath(t)
			initVault(t, path, "a")

			s := openTest(t, path)
			s.step = func(name string) error {
				if name == step {
					return errors.New("fallo simulado")
				}
				return nil
			}
			if err := s.ChangePassword(testPassword, otherPassword); err == nil {
				t.Fatal("no hubo error")
			}
			if !loadsWith(t, path, testPassword) {
				t.Error("tras el fallo, el vault debe seguir abriendo con la contraseña anterior")
			}

			s.step = nil
			if err := s.ChangePassword(testPassword, otherPassword); err != nil {
				t.Fatalf("al reintentar: %v", err)
			}
			for _, file := range []string{path, path + backupSuffix} {
				if !loadsWith(t, file, otherPassword) {
					t.Errorf("%s no abre con la contraseña nueva", filepath.Base(file))
				}
			}
		})
	}
}

func TestExportCopiesVaultAndRefusesOverwrite(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")
	dest := filepath.Join(t.TempDir(), "respaldo.bin")

	s := openTest(t, path)
	if err := s.Export(dest, otherPassword); !errors.Is(err, ErrInvalid) {
		t.Errorf("contraseña incorrecta: err = %v", err)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Fatal("se creó el respaldo con una contraseña incorrecta")
	}

	if err := s.Export(dest, testPassword); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, dest), readFile(t, path)) {
		t.Error("el respaldo no es copia del vault")
	}

	writeFile(t, dest, []byte("no pisar"))
	if err := s.Export(dest, testPassword); !errors.Is(err, ErrExists) {
		t.Errorf("destino existente: err = %v", err)
	}
	if string(readFile(t, dest)) != "no pisar" {
		t.Error("se reemplazó un archivo existente")
	}
}

func always(int, bool) bool { return true }

func TestRestoreIntoEmptyLocation(t *testing.T) {
	source := vaultPath(t)
	initVault(t, source, "a", "b")
	path := vaultPath(t)

	s := openTest(t, path)
	confirmed := false
	result, err := s.Restore(source, testPassword, func(entries int, replacing bool) bool {
		confirmed = true
		if entries != 2 || replacing {
			t.Errorf("entries = %d, replacing = %v", entries, replacing)
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if !confirmed {
		t.Error("no se pidió confirmación")
	}
	if result.Entries != 2 || result.Previous != "" {
		t.Errorf("resultado = %+v", result)
	}
	s.Close()
	if got := names(t, path); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("cuentas = %v", got)
	}
}

func TestRestoreKeepsReplacedVaultApart(t *testing.T) {
	source := vaultPath(t)
	initVault(t, source, "del-respaldo")
	path := vaultPath(t)
	initVault(t, path, "actual", "otra")
	previous := readFile(t, path)
	backup := readFile(t, path+backupSuffix)

	s := openTest(t, path)
	result, err := s.Restore(source, testPassword, always)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filepath.Base(result.Previous), "pre-restore") {
		t.Errorf("Previous = %q", result.Previous)
	}
	if !bytes.Equal(readFile(t, result.Previous), previous) {
		t.Error("la copia no es el vault reemplazado")
	}
	if !bytes.Equal(readFile(t, path+backupSuffix), backup) {
		t.Error("Restore no debe tocar el .bak")
	}
	if err := s.Save(testPassword); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("Save sin volver a cargar: err = %v", err)
	}
	s.Close()
	if got := names(t, path); !slices.Equal(got, []string{"del-respaldo"}) {
		t.Errorf("cuentas = %v", got)
	}
}

func TestRestoreRecoversCorruptVaultFromBackup(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")
	writeFile(t, path, []byte("vault dañado"))

	s := openTest(t, path)
	if _, err := s.Restore(path+backupSuffix, testPassword, always); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if got := names(t, path); got != nil {
		t.Errorf("cuentas = %v; el .bak es la versión vacía inicial", got)
	}
}

func TestRestoreLeavesEverythingWhenItCannotProceed(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")
	before := readFile(t, path)
	source := vaultPath(t)
	initVault(t, source, "b")

	noCall := func(int, bool) bool {
		t.Error("confirm no debe llamarse con un respaldo no válido")
		return false
	}

	s := openTest(t, path)
	if _, err := s.Restore(source, otherPassword, noCall); !errors.Is(err, ErrInvalid) {
		t.Errorf("contraseña incorrecta: err = %v", err)
	}
	if _, err := s.Restore(source+"-no-existe", testPassword, noCall); err == nil {
		t.Error("archivo inexistente: no hubo error")
	}
	if _, err := s.Restore(source, testPassword, func(int, bool) bool { return false }); !errors.Is(err, ErrCanceled) {
		t.Errorf("cancelado: err = %v", err)
	}

	if !bytes.Equal(readFile(t, path), before) {
		t.Error("el vault cambió")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "pre-restore") {
			t.Errorf("copia innecesaria: %s", e.Name())
		}
	}
}

func TestRestoreFailureKeepsVaultReadable(t *testing.T) {
	for _, step := range []string{"previous:write", "previous:rename", "vault:write", "vault:rename"} {
		t.Run(step, func(t *testing.T) {
			source := vaultPath(t)
			initVault(t, source, "b")
			path := vaultPath(t)
			initVault(t, path, "a")

			s := openTest(t, path)
			s.step = func(name string) error {
				if name == step {
					return errors.New("fallo simulado")
				}
				return nil
			}
			if _, err := s.Restore(source, testPassword, always); err == nil {
				t.Fatal("no hubo error")
			}
			s.Close()
			if got := names(t, path); !slices.Equal(got, []string{"a"}) {
				t.Errorf("cuentas = %v", got)
			}
		})
	}
}

func TestMaintenanceRejectsClosedStore(t *testing.T) {
	path := vaultPath(t)
	initVault(t, path, "a")
	s := openTest(t, path)
	s.Close()

	if err := s.ChangePassword(testPassword, otherPassword); !errors.Is(err, ErrClosed) {
		t.Errorf("ChangePassword: err = %v", err)
	}
	if err := s.Export(path+"-copia", testPassword); !errors.Is(err, ErrClosed) {
		t.Errorf("Export: err = %v", err)
	}
	if _, err := s.Restore(path, testPassword, always); !errors.Is(err, ErrClosed) {
		t.Errorf("Restore: err = %v", err)
	}
}
