// Package otpauth convierte cuentas 2FA desde y hacia URIs otpauth://.
//
// Estas URIs contienen secretos en claro. Los errores de net/url incluyen el
// texto que recibieron, así que aquí nunca se propagan ni se citan valores de
// la URI en los mensajes de error.
package otpauth

import (
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"piko2fa/internal/model"
)

// ErrUnsupportedType indica una URI válida de un tipo no admitido, como HOTP.
var ErrUnsupportedType = errors.New("otpauth: solo se admiten cuentas TOTP")

var secretEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Parse convierte una URI otpauth:// en una cuenta nueva.
func Parse(uri string) (model.Entry, error) {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil {
		return model.Entry{}, errors.New("otpauth: URI no válida")
	}
	if u.Scheme != "otpauth" {
		return model.Entry{}, errors.New("otpauth: la URI no empieza por otpauth://")
	}
	switch strings.ToLower(u.Host) {
	case "totp":
	case "hotp":
		return model.Entry{}, ErrUnsupportedType
	default:
		return model.Entry{}, errors.New("otpauth: tipo de cuenta desconocido")
	}

	// u.Query descarta en silencio lo que no entiende; ParseQuery lo rechaza.
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return model.Entry{}, errors.New("otpauth: parámetros no válidos")
	}
	for _, values := range query {
		if len(values) > 1 {
			return model.Entry{}, errors.New("otpauth: parámetro repetido")
		}
	}

	if !query.Has("secret") {
		return model.Entry{}, errors.New("otpauth: falta el secreto")
	}
	secret, err := DecodeSecret(query.Get("secret"))
	if err != nil {
		return model.Entry{}, err
	}

	algorithm := model.DefaultAlgorithm
	if query.Has("algorithm") {
		algorithm = strings.ToUpper(query.Get("algorithm"))
	}
	digits, err := intParam(query, "digits", model.DefaultDigits)
	if err != nil {
		return model.Entry{}, err
	}
	period, err := intParam(query, "period", model.DefaultPeriod)
	if err != nil {
		return model.Entry{}, err
	}

	name, issuer := parseLabel(u.Path, query.Get("issuer"))

	e, err := model.New(name, issuer, secret, algorithm, digits, period)
	if err != nil {
		return model.Entry{}, fmt.Errorf("otpauth: %w", err)
	}
	return e, nil
}

// Format genera la URI otpauth:// de una cuenta. El resultado contiene el
// secreto en claro.
func Format(e model.Entry) (string, error) {
	if err := e.Validate(); err != nil {
		return "", fmt.Errorf("otpauth: %w", err)
	}

	label := e.Name
	query := url.Values{}
	query.Set("secret", EncodeSecret(e.Secret))
	query.Set("algorithm", e.Algorithm)
	query.Set("digits", strconv.Itoa(e.Digits))
	query.Set("period", strconv.Itoa(e.Period))
	if e.Issuer != "" {
		label = e.Issuer + ":" + e.Name
		query.Set("issuer", e.Issuer)
	}

	u := url.URL{
		Scheme: "otpauth",
		Host:   model.TypeTOTP,
		Path:   "/" + label,
		// No todas las apps entienden "+" como espacio en la consulta.
		RawQuery: strings.ReplaceAll(query.Encode(), "+", "%20"),
	}
	return u.String(), nil
}

// DecodeSecret decodifica un secreto en base32, sin distinguir mayúsculas y
// tolerando espacios y la ausencia de relleno.
func DecodeSecret(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	s = strings.TrimRight(strings.ToUpper(s), "=")
	if s == "" {
		return nil, errors.New("otpauth: secreto vacío")
	}
	// DecodeString acepta estas longitudes imposibles sin dar error: en base32
	// solo pueden sobrar 0, 2, 4, 5 o 7 caracteres de un bloque de 8.
	switch len(s) % 8 {
	case 1, 3, 6:
		return nil, errors.New("otpauth: secreto base32 no válido")
	}
	secret, err := secretEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("otpauth: secreto base32 no válido")
	}
	return secret, nil
}

// EncodeSecret codifica un secreto en base32, sin relleno.
func EncodeSecret(secret []byte) string {
	return secretEncoding.EncodeToString(secret)
}

// parseLabel obtiene la cuenta y el emisor de la etiqueta "Emisor:cuenta". El
// parámetro issuer tiene prioridad sobre el emisor de la etiqueta.
func parseLabel(path, issuerParam string) (name, issuer string) {
	label := strings.TrimPrefix(path, "/")
	issuer = strings.TrimSpace(issuerParam)

	// El prefijo exacto permite emisores que contienen ":".
	if rest, ok := strings.CutPrefix(label, issuer+":"); ok && issuer != "" {
		return strings.TrimSpace(rest), issuer
	}
	if labelIssuer, rest, ok := strings.Cut(label, ":"); ok {
		if issuer == "" {
			issuer = strings.TrimSpace(labelIssuer)
		}
		return strings.TrimSpace(rest), issuer
	}
	return strings.TrimSpace(label), issuer
}

func intParam(query url.Values, key string, fallback int) (int, error) {
	if !query.Has(key) {
		return fallback, nil
	}
	n, err := strconv.Atoi(query.Get(key))
	if err != nil {
		return 0, fmt.Errorf("otpauth: valor no válido en %q", key)
	}
	return n, nil
}
