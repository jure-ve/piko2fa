package qrimage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// Texto falso, del tamaño aproximado de un QR real de Google Authenticator con
// unas 10 cuentas.
var longText = "otpauth-migration://offline?data=" + strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo%3D", 30)

func encodeQR(t *testing.T, text string, size int) image.Image {
	t.Helper()
	matrix, err := qrcode.NewQRCodeWriter().Encode(text, gozxing.BarcodeFormat_QR_CODE, size, size, nil)
	if err != nil {
		t.Fatal(err)
	}
	return matrix
}

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func encodeJPEG(t *testing.T, img image.Image, quality int) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// photoOf simula una foto: el QR sobre un fondo mayor, girado, con luz desigual
// y ruido.
func photoOf(qr image.Image, width, height int, degrees, noise float64) image.Image {
	rng := rand.New(rand.NewPCG(1, 2))
	angle := degrees * math.Pi / 180
	sin, cos := math.Sincos(angle)
	bounds := qr.Bounds()
	centerX, centerY := float64(width)/2, float64(height)/2

	photo := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := range height {
		for x := range width {
			// Giro inverso, para saber qué punto del QR cae en este píxel.
			dx, dy := float64(x)-centerX, float64(y)-centerY
			qx := int(cos*dx+sin*dy) + bounds.Dx()/2
			qy := int(-sin*dx+cos*dy) + bounds.Dy()/2

			value := 120.0 // fondo
			if image.Pt(qx, qy).In(bounds) {
				if r, _, _, _ := qr.At(qx, qy).RGBA(); r > 0x7fff {
					value = 225
				} else {
					value = 35
				}
			}
			value *= 0.8 + 0.2*float64(x)/float64(width) // luz desigual
			value += (rng.Float64() - 0.5) * noise
			level := uint8(max(0, min(255, value)))
			photo.SetRGBA(x, y, color.RGBA{level, level, level, 255})
		}
	}
	return photo
}

// screenPhotoOf simula la foto de una pantalla con una webcam: la rejilla de
// píxeles de la pantalla se superpone al QR.
func screenPhotoOf(qr image.Image, width, height, gridStep int) image.Image {
	photo := photoOf(qr, width, height, 1, 20).(*image.RGBA)
	for y := range height {
		for x := range width {
			if x%gridStep == 0 || y%gridStep == 0 {
				c := photo.RGBAAt(x, y)
				level := uint8(float64(c.R) * 0.45)
				photo.SetRGBA(x, y, color.RGBA{level, level, level, 255})
			}
		}
	}
	return photo
}

func TestDecodeReadsScreenPhotoThatCannotBeHalved(t *testing.T) {
	text := longText[:567]
	for _, gridStep := range []int{2, 3, 4} {
		photo := screenPhotoOf(encodeQR(t, text, 900), 1007, 983, gridStep)
		path := filepath.Join(t.TempDir(), "qr.jpg")
		if err := os.WriteFile(path, encodeJPEG(t, photo, 85), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := Decode(path)
		if err != nil {
			t.Errorf("rejilla de %d px: %v", gridStep, err)
			continue
		}
		if got != text {
			t.Errorf("rejilla de %d px: texto incorrecto", gridStep)
		}
	}
}

func TestDecodeReadsImages(t *testing.T) {
	tests := []struct {
		name string
		data func(t *testing.T) []byte
	}{
		{"PNG", func(t *testing.T) []byte { return encodePNG(t, encodeQR(t, longText, 800)) }},
		{"JPEG", func(t *testing.T) []byte { return encodeJPEG(t, encodeQR(t, longText, 800), 80) }},
		{"PNG con tamaño justo", func(t *testing.T) []byte { return encodePNG(t, encodeQR(t, longText, 1)) }},
		{"captura grande con el QR en una zona", func(t *testing.T) []byte {
			canvas := image.NewRGBA(image.Rect(0, 0, 1440, 3000))
			draw.Draw(canvas, canvas.Bounds(), image.NewUniform(color.RGBA{30, 30, 30, 255}), image.Point{}, draw.Src)
			qr := encodeQR(t, longText, 1000)
			draw.Draw(canvas, image.Rect(220, 900, 1220, 1900), qr, image.Point{}, draw.Src)
			return encodePNG(t, canvas)
		}},
		{"PNG con transparencia", func(t *testing.T) []byte {
			qr := encodeQR(t, longText, 800)
			img := image.NewNRGBA(qr.Bounds())
			for y := range qr.Bounds().Dy() {
				for x := range qr.Bounds().Dx() {
					// Módulos negros opacos sobre fondo transparente.
					if r, _, _, _ := qr.At(x, y).RGBA(); r <= 0x7fff {
						img.SetNRGBA(x, y, color.NRGBA{0, 0, 0, 255})
					}
				}
			}
			return encodePNG(t, img)
		}},
		{"foto recta y limpia", func(t *testing.T) []byte {
			return encodeJPEG(t, photoOf(encodeQR(t, longText, 1200), 2000, 1600, 0, 10), 85)
		}},
		{"foto girada con ruido", func(t *testing.T) []byte {
			return encodeJPEG(t, photoOf(encodeQR(t, longText, 1400), 2400, 2000, 4, 40), 75)
		}},
		{"foto muy grande y con mucho ruido", func(t *testing.T) []byte {
			return encodeJPEG(t, photoOf(encodeQR(t, longText, 2400), 4000, 3000, 2, 90), 70)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "qr.img")
			if err := os.WriteFile(path, tt.data(t), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := Decode(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != longText {
				t.Errorf("texto incorrecto: %d bytes, se esperaban %d", len(got), len(longText))
			}
		})
	}
}

// pngHeader construye el inicio de un PNG válido con las dimensiones indicadas,
// sin los píxeles.
func pngHeader(width, height uint32) []byte {
	ihdr := binary.BigEndian.AppendUint32([]byte("IHDR"), width)
	ihdr = binary.BigEndian.AppendUint32(ihdr, height)
	ihdr = append(ihdr, 8, 0, 0, 0, 0)

	out := []byte("\x89PNG\r\n\x1a\n")
	out = binary.BigEndian.AppendUint32(out, 13)
	out = append(out, ihdr...)
	return binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(ihdr))
}

func TestDecodeReportsFailures(t *testing.T) {
	blank := image.NewGray(image.Rect(0, 0, 800, 800))
	draw.Draw(blank, blank.Bounds(), image.White, image.Point{}, draw.Src)
	valid := encodePNG(t, encodeQR(t, "texto", 400))

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"imagen sin QR", encodePNG(t, blank), ErrNoQR},
		{"archivo de texto", []byte("esto no es una imagen"), ErrUnsupportedFormat},
		{"archivo vacío", nil, ErrUnsupportedFormat},
		{"HEIC", []byte("\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic"), ErrUnsupportedFormat},
		{"dimensiones enormes", pngHeader(30000, 30000), ErrTooLarge},
		{"dimensiones que desbordan", pngHeader(0x7fffffff, 0x7fffffff), nil},
		{"PNG truncado", valid[:len(valid)/2], nil},
		{"solo la cabecera de un PNG", pngHeader(100, 100), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "qr.img")
			if err := os.WriteFile(path, tt.data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Decode(path)
			if err == nil {
				t.Fatal("no hubo error")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("err = %v, se esperaba %v", err, tt.want)
			}
		})
	}
}

func TestDecodeMissingFile(t *testing.T) {
	if _, err := Decode(filepath.Join(t.TempDir(), "no-existe.png")); err == nil {
		t.Error("no hubo error")
	}
}

func TestShrinkStopsAtMinimumSize(t *testing.T) {
	if got := shrink(image.NewGray(image.Rect(0, 0, 1000, 1000))); got == nil || got.Rect.Dx() != 800 {
		t.Errorf("no redujo una imagen que aún cabe: %v", got)
	}
	if got := shrink(image.NewGray(image.Rect(0, 0, minScaledSide, minScaledSide*4))); got != nil {
		t.Error("redujo por debajo del mínimo")
	}
}

func TestResizeKeepsUniformLevel(t *testing.T) {
	src := image.NewGray(image.Rect(0, 0, 10, 10))
	draw.Draw(src, src.Bounds(), image.NewUniform(color.Gray{Y: 200}), image.Point{}, draw.Src)
	for _, factor := range []float64{0.8, 1.5} {
		for _, level := range resize(src, factor).Pix {
			if level != 200 {
				t.Fatalf("factor %v: nivel = %d", factor, level)
			}
		}
	}
	for _, level := range smooth(src).Pix {
		if level != 200 {
			t.Fatalf("smooth: nivel = %d", level)
		}
	}
}

func TestToGrayCompositesOverWhite(t *testing.T) {
	img := image.NewNRGBA(image.Rect(5, 5, 7, 6))
	img.SetNRGBA(5, 5, color.NRGBA{0, 0, 0, 0})
	img.SetNRGBA(6, 5, color.NRGBA{0, 0, 0, 255})

	gray := toGray(img)
	if got := gray.GrayAt(0, 0).Y; got != 255 {
		t.Errorf("transparente = %d, se esperaba blanco", got)
	}
	if got := gray.GrayAt(1, 0).Y; got != 0 {
		t.Errorf("negro opaco = %d", got)
	}
}
