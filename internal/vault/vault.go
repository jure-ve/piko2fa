// Package vault guarda las cuentas en un archivo cifrado completo: se descifra
// todo al abrir, se opera en memoria y se vuelve a cifrar al guardar.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/gofrs/flock"

	"piko2fa/internal/model"
)

const (
	schemaVersion = 1

	backupSuffix = ".bak"
	lockSuffix   = ".lock"

	lockTimeout   = 5 * time.Second
	lockRetry     = 50 * time.Millisecond
	renameRetries = 10
	renameDelay   = 100 * time.Millisecond
)

var (
	// ErrInvalid no distingue una contraseña incorrecta de un archivo alterado.
	ErrInvalid            = errors.New("vault: contraseña incorrecta o archivo dañado")
	ErrUnsupportedVersion = errors.New("vault: versión de formato no admitida")
	ErrNoVault            = errors.New("vault: el vault no existe")
	ErrExists             = errors.New("vault: el vault ya existe")
	ErrLocked             = errors.New("vault: otro proceso está usando el vault")
	ErrNotLoaded          = errors.New("vault: el vault no está abierto")
	ErrClosed             = errors.New("vault: el almacén está cerrado")
	ErrEmptyPassword      = errors.New("vault: la contraseña está vacía")
	ErrEntryNotFound      = errors.New("vault: la cuenta no existe")
	ErrDuplicateID        = errors.New("vault: ya existe una cuenta con ese ID")
)

// Store aísla el formato de almacenamiento del resto de la aplicación.
type Store interface {
	Init(password []byte) error
	Load(password []byte) error
	Save(password []byte) error
	List() []model.Entry
	Get(id string) (model.Entry, error)
	Add(e model.Entry) error
	Remove(id string) error
	Find(query string) []model.Entry
	Close() error
}

var _ Store = (*FileStore)(nil)

type contents struct {
	Schema  int           `json:"schema"`
	Entries []model.Entry `json:"entries"`
}

// FileStore implementa Store sobre un archivo. Mantiene el bloqueo entre
// procesos desde Open hasta Close, para cubrir todo el ciclo de leer, modificar
// y guardar. Conviene pedir la contraseña antes de Open, para no retener el
// bloqueo mientras se escribe. No es seguro para uso concurrente dentro de un
// mismo proceso.
//
// Las cuentas devueltas comparten sus secretos con el almacén: no se deben
// modificar y Close los pone a cero.
type FileStore struct {
	path    string
	lock    *flock.Flock
	params  kdfParams
	entries []model.Entry
	loaded  bool
	closed  bool

	// step, si no es nil, se llama antes de cada operación de escritura. Permite
	// simular fallos en los tests.
	step func(name string) error
}

// DefaultPath devuelve la ubicación del vault. En Windows usa %LocalAppData%,
// que no se sincroniza con el perfil y que Go expone como UserCacheDir.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if runtime.GOOS == "windows" {
		dir, err = os.UserCacheDir()
	}
	if err != nil {
		return "", fmt.Errorf("vault: localizar el directorio: %w", err)
	}
	return filepath.Join(dir, "piko2fa", "vault.bin"), nil
}

// Open crea el directorio si hace falta y toma el bloqueo. No lee el vault.
func Open(path string) (*FileStore, error) {
	return open(path, lockTimeout)
}

func open(path string, timeout time.Duration) (*FileStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("vault: crear el directorio: %w", err)
	}

	// El bloqueo va en un archivo aparte porque vault.bin se reemplaza al guardar.
	lock := flock.New(path + lockSuffix)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ok, err := lock.TryLockContext(ctx, lockRetry)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return nil, fmt.Errorf("vault: tomar el bloqueo: %w", err)
	}
	if !ok {
		return nil, ErrLocked
	}
	return &FileStore{path: path, lock: lock, params: defaultParams}, nil
}

// Init crea un vault vacío. Nunca reemplaza uno existente.
func (s *FileStore) Init(password []byte) error {
	if s.closed {
		return ErrClosed
	}
	if len(password) == 0 {
		return ErrEmptyPassword
	}
	if _, err := os.Stat(s.path); err == nil {
		return ErrExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("vault: comprobar el archivo: %w", pathless(err))
	}

	s.setEntries(nil)
	if err := s.writeVault(password); err != nil {
		return err
	}
	s.loaded = true
	return nil
}

// Load descifra el vault. Si falla, las cuentas en memoria no cambian.
func (s *FileStore) Load(password []byte) error {
	if s.closed {
		return ErrClosed
	}
	data, err := s.readVault()
	if err != nil {
		return err
	}
	plaintext, err := unseal(password, data)
	if err != nil {
		return err
	}
	defer clear(plaintext)

	entries, err := decodeContents(plaintext)
	if err != nil {
		return err
	}
	s.setEntries(entries)
	s.loaded = true
	return nil
}

// decodeContents interpreta el contenido descifrado, todo o nada.
func decodeContents(plaintext []byte) ([]model.Entry, error) {
	var c contents
	if err := json.Unmarshal(plaintext, &c); err != nil {
		return nil, ErrInvalid
	}
	if c.Schema != schemaVersion {
		zeroSecrets(c.Entries)
		return nil, ErrUnsupportedVersion
	}
	for _, e := range c.Entries {
		if err := e.Validate(); err != nil {
			zeroSecrets(c.Entries)
			return nil, ErrInvalid
		}
	}
	return c.Entries, nil
}

// Save guarda las cuentas con una sal y un nonce nuevos, conservando la versión
// anterior en el .bak. Antes comprueba que el vault actual abre con password:
// así, un archivo dañado no reemplaza a un respaldo bueno, y una contraseña
// distinta no vuelve a cifrar el vault sin querer. Si falla cualquier paso,
// vault.bin sigue siendo abrible.
func (s *FileStore) Save(password []byte) error {
	if s.closed {
		return ErrClosed
	}
	if !s.loaded {
		return ErrNotLoaded
	}
	if len(password) == 0 {
		return ErrEmptyPassword
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

	if err := s.writeAtomic(s.path+backupSuffix, current, "backup"); err != nil {
		return err
	}
	return s.writeVault(password)
}

// List devuelve todas las cuentas.
func (s *FileStore) List() []model.Entry {
	return slices.Clone(s.entries)
}

// Get devuelve la cuenta con ese ID.
func (s *FileStore) Get(id string) (model.Entry, error) {
	for _, e := range s.entries {
		if e.ID == id {
			return e, nil
		}
	}
	return model.Entry{}, ErrEntryNotFound
}

// Add añade una cuenta en memoria. Se conserva hasta el siguiente Save.
func (s *FileStore) Add(e model.Entry) error {
	if s.closed {
		return ErrClosed
	}
	if !s.loaded {
		return ErrNotLoaded
	}
	if err := e.Validate(); err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	if e.ID == "" {
		return errors.New("vault: cuenta sin ID")
	}
	if slices.ContainsFunc(s.entries, func(other model.Entry) bool { return other.ID == e.ID }) {
		return ErrDuplicateID
	}

	e.Secret = bytes.Clone(e.Secret)
	s.entries = append(s.entries, e)
	return nil
}

// Remove quita una cuenta de la memoria. Se conserva hasta el siguiente Save.
func (s *FileStore) Remove(id string) error {
	if s.closed {
		return ErrClosed
	}
	if !s.loaded {
		return ErrNotLoaded
	}
	i := slices.IndexFunc(s.entries, func(e model.Entry) bool { return e.ID == id })
	if i < 0 {
		return ErrEntryNotFound
	}
	clear(s.entries[i].Secret)
	s.entries = slices.Delete(s.entries, i, i+1)
	return nil
}

// Find devuelve las cuentas cuyo nombre o emisor contienen query, sin distinguir
// mayúsculas. Una consulta vacía devuelve todas.
func (s *FileStore) Find(query string) []model.Entry {
	query = strings.ToLower(query)
	var found []model.Entry
	for _, e := range s.entries {
		if strings.Contains(strings.ToLower(e.Name), query) || strings.Contains(strings.ToLower(e.Issuer), query) {
			found = append(found, e)
		}
	}
	return found
}

// Close pone a cero los secretos y libera el bloqueo. Poner a cero es solo un
// esfuerzo parcial: Go puede haber dejado otras copias en memoria.
func (s *FileStore) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	s.loaded = false
	s.setEntries(nil)
	if err := s.lock.Unlock(); err != nil {
		return fmt.Errorf("vault: liberar el bloqueo: %w", err)
	}
	return nil
}

func (s *FileStore) setEntries(entries []model.Entry) {
	zeroSecrets(s.entries)
	s.entries = entries
}

func zeroSecrets(entries []model.Entry) {
	for _, e := range entries {
		clear(e.Secret)
	}
}

func (s *FileStore) readVault() ([]byte, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoVault
	}
	if err != nil {
		return nil, fmt.Errorf("vault: leer el archivo: %w", pathless(err))
	}
	return data, nil
}

func (s *FileStore) writeVault(password []byte) error {
	entries := s.entries
	if entries == nil {
		entries = []model.Entry{}
	}
	plaintext, err := json.Marshal(contents{Schema: schemaVersion, Entries: entries})
	if err != nil {
		return errors.New("vault: no se pudo serializar el contenido")
	}
	defer clear(plaintext)

	data, err := seal(password, s.params, plaintext)
	if err != nil {
		return err
	}
	return s.writeAtomic(s.path, data, "vault")
}

// writeAtomic reemplaza path sin que deje de existir en ningún momento: un
// lector ve el archivo anterior o el nuevo, nunca uno a medias.
func (s *FileStore) writeAtomic(path string, data []byte, label string) error {
	if err := s.runStep(label + ":create"); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".piko2fa-*.tmp")
	if err != nil {
		return fmt.Errorf("vault: crear el temporal: %w", pathless(err))
	}
	renamed := false
	defer func() {
		if !renamed {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()

	if err := s.runStep(label + ":write"); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("vault: escribir el temporal: %w", pathless(err))
	}
	if err := s.runStep(label + ":sync"); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("vault: sincronizar el temporal: %w", pathless(err))
	}
	if err := s.runStep(label + ":close"); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("vault: cerrar el temporal: %w", pathless(err))
	}
	if err := s.rename(tmp.Name(), path, label); err != nil {
		return err
	}
	renamed = true

	if err := s.runStep(label + ":syncdir"); err != nil {
		return err
	}
	return syncDir(dir)
}

// rename reintenta en Windows, donde falla mientras otro proceso, como un
// antivirus, tiene abierto el archivo de destino.
func (s *FileStore) rename(from, to, label string) error {
	attempts := 1
	if runtime.GOOS == "windows" {
		attempts = renameRetries
	}

	var err error
	for i := range attempts {
		if i > 0 {
			time.Sleep(renameDelay)
		}
		if err = s.runStep(label + ":rename"); err != nil {
			continue
		}
		if err = os.Rename(from, to); err == nil {
			return nil
		}
	}
	return fmt.Errorf("vault: reemplazar el archivo: %w", pathless(err))
}

// pathless quita la ruta de los errores del sistema. Export y Restore reciben
// rutas escritas por el usuario, que podrían ser una URI pegada por error.
func pathless(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return linkErr.Err
	}
	return err
}

func (s *FileStore) runStep(name string) error {
	if s.step == nil {
		return nil
	}
	return s.step(name)
}

// syncDir hace duradero el rename en Linux y macOS. Windows no permite
// sincronizar directorios, y algunos sistemas de archivos devuelven EINVAL.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("vault: abrir el directorio: %w", pathless(err))
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("vault: sincronizar el directorio: %w", pathless(err))
	}
	return nil
}
