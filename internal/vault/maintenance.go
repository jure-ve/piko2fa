package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"
)

var (
	// ErrCanceled indica que quien llamó a Restore decidió no continuar.
	ErrCanceled = errors.New("vault: operación cancelada")
	// ErrBackupUnreadable impide dejar un .bak que aún abriría con la contraseña
	// anterior. Decidir qué hacer con ese archivo le corresponde al usuario.
	ErrBackupUnreadable = errors.New("vault: no se pudo volver a cifrar vault.bin.bak; muévelo a otro lugar y vuelve a intentarlo")
)

// ChangePassword vuelve a cifrar el vault y el .bak con otra contraseña. Cifra
// primero el .bak: si falla a medias, el vault sigue abriendo con la contraseña
// anterior y se puede repetir la operación.
func (s *FileStore) ChangePassword(oldPassword, newPassword []byte) error {
	if s.closed {
		return ErrClosed
	}
	if len(newPassword) == 0 {
		return ErrEmptyPassword
	}

	current, err := s.readVault()
	if err != nil {
		return err
	}
	plaintext, err := unseal(oldPassword, current)
	if err != nil {
		return err
	}
	defer clear(plaintext)

	if err := s.reencryptBackup(oldPassword, newPassword); err != nil {
		return err
	}
	data, err := seal(newPassword, s.params, plaintext)
	if err != nil {
		return err
	}
	return s.writeAtomic(s.path, data, "vault")
}

func (s *FileStore) reencryptBackup(oldPassword, newPassword []byte) error {
	path := s.path + backupSuffix
	backup, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("vault: leer el respaldo: %w", pathless(err))
	}

	plaintext, err := unseal(oldPassword, backup)
	if err != nil {
		// Puede venir de un cambio anterior interrumpido, ya con la contraseña nueva.
		if done, err := unseal(newPassword, backup); err == nil {
			clear(done)
			return nil
		}
		return ErrBackupUnreadable
	}
	defer clear(plaintext)

	data, err := seal(newPassword, s.params, plaintext)
	if err != nil {
		return err
	}
	return s.writeAtomic(path, data, "backup")
}

// Export copia el vault cifrado a dest, tras comprobar que abre con password.
// El respaldo conserva esa contraseña. Nunca reemplaza un archivo existente.
func (s *FileStore) Export(dest string, password []byte) error {
	if s.closed {
		return ErrClosed
	}
	if _, err := os.Stat(dest); err == nil {
		return ErrExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("vault: comprobar el destino: %w", pathless(err))
	}

	current, err := s.readVault()
	if err != nil {
		return err
	}
	plaintext, err := unseal(password, current)
	if err != nil {
		return err
	}
	clear(plaintext)

	return s.writeAtomic(dest, current, "export")
}

// RestoreResult describe una restauración terminada.
type RestoreResult struct {
	Entries  int
	Previous string // copia del vault reemplazado; vacío si no había ninguno
}

// Restore reemplaza el vault por un respaldo, que también puede ser el .bak, y
// el vault pasa a usar la contraseña del respaldo. confirm recibe el número de
// cuentas del respaldo, ya validado, y si hay un vault que se va a reemplazar.
//
// El vault reemplazado se guarda en un archivo propio y nunca en el .bak, porque
// podría estar dañado: se restaura justo cuando algo ha ido mal.
func (s *FileStore) Restore(src string, password []byte, confirm func(entries int, replacing bool) bool) (RestoreResult, error) {
	if s.closed {
		return RestoreResult{}, ErrClosed
	}
	backup, err := os.ReadFile(src)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("vault: leer el respaldo: %w", pathless(err))
	}
	plaintext, err := unseal(password, backup)
	if err != nil {
		return RestoreResult{}, err
	}
	defer clear(plaintext)
	entries, err := decodeContents(plaintext)
	if err != nil {
		return RestoreResult{}, err
	}
	defer zeroSecrets(entries)

	current, err := s.readVault()
	replacing := err == nil
	if err != nil && !errors.Is(err, ErrNoVault) {
		return RestoreResult{}, err
	}
	if !confirm(len(entries), replacing) {
		return RestoreResult{}, ErrCanceled
	}

	result := RestoreResult{Entries: len(entries)}
	if replacing {
		result.Previous = s.path + ".pre-restore-" + time.Now().Format("20060102-150405.000")
		if err := s.writeAtomic(result.Previous, current, "previous"); err != nil {
			return RestoreResult{}, err
		}
	}
	if err := s.writeAtomic(s.path, backup, "vault"); err != nil {
		return RestoreResult{}, err
	}

	// Lo que hubiera en memoria ya no corresponde al archivo.
	s.setEntries(nil)
	s.loaded = false
	return result, nil
}
