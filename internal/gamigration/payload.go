package gamigration

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

// Números de campo del protobuf MigrationPayload.
const (
	fieldOTPParameters protowire.Number = 1
	fieldBatchSize     protowire.Number = 3
	fieldBatchIndex    protowire.Number = 4
	fieldBatchID       protowire.Number = 5

	fieldSecret    protowire.Number = 1
	fieldName      protowire.Number = 2
	fieldIssuer    protowire.Number = 3
	fieldAlgorithm protowire.Number = 4
	fieldDigits    protowire.Number = 5
	fieldType      protowire.Number = 6
)

// Valores de los enums del protobuf.
const (
	algorithmUnspecified = 0
	algorithmSHA1        = 1
	algorithmSHA256      = 2
	algorithmSHA512      = 3
	algorithmMD5         = 4

	digitsUnspecified = 0
	digitsSix         = 1
	digitsEight       = 2

	typeHOTP = 1
	typeTOTP = 2
)

// maxBatchSize acota la lista de lotes faltantes que puede provocar un payload
// corrupto. Es muy superior a los QR de una exportación real.
const maxBatchSize = 1000

var errCorruptPayload = errors.New("contenido del QR dañado")

type account struct {
	secret    []byte
	name      string
	issuer    string
	algorithm int
	digits    int
	otpType   int
}

type payload struct {
	accounts   []account
	batchSize  int
	batchIndex int
	batchID    int32
}

// parseURI decodifica una URI otpauth-migration://. Como la URI contiene
// secretos en claro, ningún error cita su contenido ni propaga los de net/url.
func parseURI(uri string) (payload, error) {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil {
		return payload{}, errors.New("URI no válida")
	}
	if u.Scheme != "otpauth-migration" || strings.ToLower(u.Host) != "offline" {
		return payload{}, errors.New("la URI no empieza por otpauth-migration://offline")
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return payload{}, errors.New("parámetros no válidos")
	}
	values := query["data"]
	if len(values) != 1 {
		return payload{}, errors.New("la URI debe tener un único parámetro data")
	}

	// ParseQuery ya hizo el URL-decode: otro más corrompería el base64. Lo único
	// que se restaura es el "+" que algunos lectores dejan sin codificar, porque
	// ParseQuery lo convierte en espacio.
	data := strings.ReplaceAll(values[0], " ", "+")
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(data, "="))
	if err != nil {
		return payload{}, errors.New("base64 no válido")
	}
	return parsePayload(raw)
}

func parsePayload(b []byte) (payload, error) {
	var p payload
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return payload{}, errCorruptPayload
		}
		b = b[n:]

		switch num {
		case fieldOTPParameters:
			value, n := consumeBytes(typ, b)
			if n < 0 {
				return payload{}, errCorruptPayload
			}
			a, err := parseAccount(value)
			if err != nil {
				return payload{}, err
			}
			p.accounts = append(p.accounts, a)
			b = b[n:]
		case fieldBatchSize, fieldBatchIndex, fieldBatchID:
			value, n := consumeVarint(typ, b)
			if n < 0 {
				return payload{}, errCorruptPayload
			}
			// int32 en el protobuf: los negativos llegan con signo extendido.
			switch num {
			case fieldBatchSize:
				p.batchSize = int(int32(value))
			case fieldBatchIndex:
				p.batchIndex = int(int32(value))
			case fieldBatchID:
				p.batchID = int32(value)
			}
			b = b[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return payload{}, errCorruptPayload
			}
			b = b[n:]
		}
	}

	if len(p.accounts) == 0 {
		return payload{}, errors.New("el QR no contiene cuentas")
	}
	// proto3 omite los ceros: una exportación de un solo QR puede no traer tamaño.
	if p.batchSize == 0 {
		p.batchSize = 1
	}
	if p.batchSize < 0 || p.batchSize > maxBatchSize || p.batchIndex < 0 || p.batchIndex >= p.batchSize {
		return payload{}, errCorruptPayload
	}
	return p, nil
}

func parseAccount(b []byte) (account, error) {
	var a account
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return account{}, errCorruptPayload
		}
		b = b[n:]

		switch num {
		case fieldSecret, fieldName, fieldIssuer:
			value, n := consumeBytes(typ, b)
			if n < 0 {
				return account{}, errCorruptPayload
			}
			switch num {
			case fieldSecret:
				a.secret = bytes.Clone(value)
			case fieldName:
				if !utf8.Valid(value) {
					return account{}, errCorruptPayload
				}
				a.name = string(value)
			case fieldIssuer:
				if !utf8.Valid(value) {
					return account{}, errCorruptPayload
				}
				a.issuer = string(value)
			}
			b = b[n:]
		case fieldAlgorithm, fieldDigits, fieldType:
			value, n := consumeVarint(typ, b)
			if n < 0 {
				return account{}, errCorruptPayload
			}
			switch num {
			case fieldAlgorithm:
				a.algorithm = int(int32(value))
			case fieldDigits:
				a.digits = int(int32(value))
			case fieldType:
				a.otpType = int(int32(value))
			}
			b = b[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return account{}, errCorruptPayload
			}
			b = b[n:]
		}
	}
	return a, nil
}

// consumeBytes y consumeVarint devuelven un n negativo si el tipo de cable no
// es el esperado, igual que las funciones de protowire ante datos truncados.
func consumeBytes(typ protowire.Type, b []byte) ([]byte, int) {
	if typ != protowire.BytesType {
		return nil, -1
	}
	return protowire.ConsumeBytes(b)
}

func consumeVarint(typ protowire.Type, b []byte) (uint64, int) {
	if typ != protowire.VarintType {
		return 0, -1
	}
	return protowire.ConsumeVarint(b)
}
