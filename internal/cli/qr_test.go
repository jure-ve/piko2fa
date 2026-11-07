package cli

import (
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

func writeQR(t *testing.T, path, text string) string {
	t.Helper()
	matrix, err := qrcode.NewQRCodeWriter().Encode(text, gozxing.BarcodeFormat_QR_CODE, 600, 600, nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, matrix); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestImportFromQRImages(t *testing.T) {
	dir := t.TempDir()
	first := writeQR(t, filepath.Join(dir, "qr1.png"), migrationURI(7, 0, 2, ga("a", "E"), ga("b", "E")))
	second := writeQR(t, filepath.Join(dir, "qr2.png"), migrationURI(7, 1, 2, ga("c", "E")))

	e := newEnv(t)
	e.init()
	out := e.mustRun([]string{testPassword}, []string{"s"}, "import-ga", "--qr", first, second)
	shouldContain(t, out, "Recibidas: 3", "2 de 2 QR", "3 cuentas importadas", "Recuerda borrar las imágenes")
	shouldContain(t, e.list(), "E:a", "E:b", "E:c")
}

func TestImportFromQRExpandsWildcards(t *testing.T) {
	dir := t.TempDir()
	writeQR(t, filepath.Join(dir, "qr1.png"), migrationURI(7, 0, 2, ga("a", "E")))
	writeQR(t, filepath.Join(dir, "qr2.png"), migrationURI(7, 1, 2, ga("b", "E")))

	e := newEnv(t)
	e.init()
	e.mustRun([]string{testPassword}, []string{"s"}, "import-ga", "--qr", filepath.Join(dir, "*.png"))
	shouldContain(t, e.list(), "2 cuentas")

	if _, err := e.run(nil, nil, "import-ga", "--qr", filepath.Join(dir, "*.jpg")); err == nil {
		t.Error("comodín sin coincidencias: no hubo error")
	}
}

func TestImportFromQRReportsUnreadableImagesAndContinues(t *testing.T) {
	dir := t.TempDir()
	good := writeQR(t, filepath.Join(dir, "bueno.png"), migrationURI(7, 0, 2, ga("a", "E")))
	bad := filepath.Join(dir, "malo.png")
	if err := os.WriteFile(bad, []byte("no es una imagen"), 0o600); err != nil {
		t.Fatal(err)
	}

	e := newEnv(t)
	e.init()
	out := e.mustRun([]string{testPassword}, []string{"s"}, "import-ga", "--qr", good, bad)
	shouldContain(t, out, "No se pudo leer", "malo.png", "1 de 2 imágenes", "Faltan los QR: 2", "1 cuenta importada")
}

func TestImportFromQRFailsWhenNothingIsReadable(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "malo.png")
	if err := os.WriteFile(bad, []byte("no es una imagen"), 0o600); err != nil {
		t.Fatal(err)
	}

	e := newEnv(t)
	e.init()
	out, err := e.run(nil, nil, "import-ga", "--qr", bad)
	if err == nil {
		t.Fatal("no hubo error")
	}
	shouldContain(t, out, "malo.png")
	shouldContain(t, err.Error(), "lector sin conexión")
	if len(e.console.prompts) != 0 {
		t.Errorf("preguntó %v", e.console.prompts)
	}
}

func TestImportFromQRWithOtherContent(t *testing.T) {
	dir := t.TempDir()
	normal := writeQR(t, filepath.Join(dir, "normal.png"), "otpauth://totp/a?secret="+fakeBase32)

	e := newEnv(t)
	e.init()
	out := e.mustRun([]string{testPassword}, nil, "import-ga", "--qr", normal)
	shouldContain(t, out, "URI 1 no válida", "No hay cuentas nuevas")
	shouldNotContain(t, out, fakeBase32)
}

func TestImportFromQRArguments(t *testing.T) {
	uri := "otpauth-migration://offline?data=" + fakeBase32
	e := newEnv(t)
	e.init()

	for _, args := range [][]string{
		{"import-ga", "--qr"},
		{"import-ga", "--qr", "--file", "uris.txt", "a.png"},
		{"import-ga", "--qr", uri},
		{"import-ga", "--qr", "a.png", uri},
		{"import-ga", "a.png"},
	} {
		out, err := e.run(nil, nil, args...)
		if err == nil {
			t.Errorf("%v: no hubo error", args)
			continue
		}
		if strings.Contains(out+err.Error(), fakeBase32) {
			t.Errorf("%v: repite la clave: %v", args, err)
		}
		if len(e.console.prompts) != 0 {
			t.Errorf("%v: preguntó %v", args, e.console.prompts)
		}
	}
}
