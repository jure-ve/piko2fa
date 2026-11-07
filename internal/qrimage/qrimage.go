// Package qrimage lee el texto de un código QR desde un archivo de imagen.
package qrimage

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	_ "image/jpeg"
	_ "image/png"
	"os"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// Límites que evitan agotar la memoria con un archivo dañado o malicioso. Son
// muy superiores a los de una foto de teléfono.
const (
	maxFileSize = 128 << 20
	maxPixels   = 200_000_000
)

// minScaledSide evita reducir tanto la imagen que el QR deje de ser legible, y
// maxUpscaledSide, ampliar una imagen que ya tiene píxeles de sobra.
const (
	minScaledSide   = 300
	maxUpscaledSide = 2000
	shrinkFactor    = 0.8
)

var upscaleFactors = []float64{1.25, 1.5}

var (
	ErrUnsupportedFormat = errors.New("formato de imagen no admitido; usa PNG o JPEG")
	ErrTooLarge          = errors.New("la imagen es demasiado grande")
	ErrNoQR              = errors.New("no se encontró un QR legible")
)

// Decode devuelve el texto del QR que contiene la imagen. Ese texto puede ser un
// secreto, así que ningún error lo cita.
func Decode(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", errors.New("no se pudo abrir el archivo")
	}
	if info.Size() > maxFileSize {
		return "", ErrTooLarge
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("no se pudo leer el archivo")
	}
	return decodeBytes(data)
}

func decodeBytes(data []byte) (string, error) {
	config, _, err := image.DecodeConfig(bytes.NewReader(data))
	if errors.Is(err, image.ErrFormat) {
		return "", ErrUnsupportedFormat
	}
	if err != nil {
		return "", errors.New("la imagen está dañada")
	}
	if config.Width <= 0 || config.Height <= 0 || config.Width > maxPixels/config.Height {
		return "", ErrTooLarge
	}

	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", errors.New("la imagen está dañada")
	}
	return decodeImage(img)
}

// decodeImage prueba de lo más fiable a lo más costoso. Las fotos de una pantalla
// suelen leerse mejor reducidas o suavizadas, porque así se atenúan el ruido, el
// moiré y la rejilla de píxeles. Qué tamaño funciona depende de cada foto, así que
// se reduce poco a poco; ampliar es el último recurso.
func decodeImage(img image.Image) (string, error) {
	gray := toGray(img)
	for scaled := gray; scaled != nil; scaled = shrink(scaled) {
		if text, ok := tryDecodeSmoothed(scaled); ok {
			return text, nil
		}
	}
	if max(gray.Rect.Dx(), gray.Rect.Dy()) <= maxUpscaledSide {
		for _, factor := range upscaleFactors {
			if text, ok := tryDecodeSmoothed(resize(gray, factor)); ok {
				return text, nil
			}
		}
	}
	return "", ErrNoQR
}

func tryDecodeSmoothed(img *image.Gray) (string, bool) {
	if text, ok := tryDecode(img); ok {
		return text, true
	}
	return tryDecode(smooth(img))
}

func tryDecode(img *image.Gray) (string, bool) {
	source := gozxing.NewLuminanceSourceFromImage(img)
	for _, newBinarizer := range []func(gozxing.LuminanceSource) gozxing.Binarizer{
		gozxing.NewHybridBinarizer,
		gozxing.NewGlobalHistgramBinarizer,
	} {
		if text, ok := tryBinarizer(newBinarizer(source)); ok {
			return text, true
		}
	}
	return "", false
}

// tryBinarizer convierte los pánicos en fallos de lectura: la librería recorre
// datos de una imagen que puede estar dañada.
func tryBinarizer(binarizer gozxing.Binarizer) (text string, ok bool) {
	defer func() {
		if recover() != nil {
			text, ok = "", false
		}
	}()

	bitmap, err := gozxing.NewBinaryBitmap(binarizer)
	if err != nil {
		return "", false
	}
	hints := map[gozxing.DecodeHintType]interface{}{gozxing.DecodeHintType_TRY_HARDER: true}
	result, err := qrcode.NewQRCodeReader().Decode(bitmap, hints)
	if err != nil {
		return "", false
	}
	return result.GetText(), true
}

// toGray convierte a grises sobre fondo blanco: en un PNG con transparencia, los
// píxeles transparentes son el fondo del QR, no negro.
func toGray(img image.Image) *image.Gray {
	bounds := img.Bounds()
	gray := image.NewGray(image.Rect(0, 0, bounds.Dx(), bounds.Dy()))
	for y := range bounds.Dy() {
		for x := range bounds.Dx() {
			r, g, b, a := img.At(bounds.Min.X+x, bounds.Min.Y+y).RGBA()
			background := 0xffff - a
			c := color.RGBA64{R: uint16(r + background), G: uint16(g + background), B: uint16(b + background), A: 0xffff}
			gray.SetGray(x, y, color.GrayModel.Convert(c).(color.Gray))
		}
	}
	return gray
}

// shrink da el siguiente tamaño menor. Devuelve nil si la imagen ya es demasiado
// pequeña. Al ser un paso corto, la interpolación no pierde líneas de píxeles.
func shrink(src *image.Gray) *image.Gray {
	if float64(min(src.Rect.Dx(), src.Rect.Dy()))*shrinkFactor < minScaledSide {
		return nil
	}
	return resize(src, shrinkFactor)
}

// resize cambia el tamaño con interpolación bilineal.
func resize(src *image.Gray, factor float64) *image.Gray {
	srcWidth, srcHeight := src.Rect.Dx(), src.Rect.Dy()
	width, height := int(float64(srcWidth)*factor), int(float64(srcHeight)*factor)
	dst := image.NewGray(image.Rect(0, 0, width, height))
	for y := range height {
		sy := float64(y) / factor
		y0 := int(sy)
		y1 := min(y0+1, srcHeight-1)
		wy := sy - float64(y0)
		for x := range width {
			sx := float64(x) / factor
			x0 := int(sx)
			x1 := min(x0+1, srcWidth-1)
			wx := sx - float64(x0)
			top := float64(src.GrayAt(x0, y0).Y)*(1-wx) + float64(src.GrayAt(x1, y0).Y)*wx
			bottom := float64(src.GrayAt(x0, y1).Y)*(1-wx) + float64(src.GrayAt(x1, y1).Y)*wx
			dst.SetGray(x, y, color.Gray{Y: uint8(top*(1-wy) + bottom*wy)})
		}
	}
	return dst
}

// smooth promedia cada píxel con sus vecinos, en un bloque de 3x3.
func smooth(src *image.Gray) *image.Gray {
	width, height := src.Rect.Dx(), src.Rect.Dy()
	dst := image.NewGray(image.Rect(0, 0, width, height))
	for y := range height {
		for x := range width {
			sum, count := 0, 0
			for ny := max(y-1, 0); ny <= min(y+1, height-1); ny++ {
				for nx := max(x-1, 0); nx <= min(x+1, width-1); nx++ {
					sum += int(src.GrayAt(nx, ny).Y)
					count++
				}
			}
			dst.SetGray(x, y, color.Gray{Y: uint8(sum / count)})
		}
	}
	return dst
}
