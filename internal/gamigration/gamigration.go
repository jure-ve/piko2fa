// Package gamigration importa cuentas de la exportación por QR de Google
// Authenticator (URIs otpauth-migration://).
package gamigration

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"piko2fa/internal/model"
	"piko2fa/internal/totp"
)

// Result es el resultado de una importación. Se cumple siempre que
// len(Entries) + len(Duplicates) + len(Conflicts) + len(Rejected) == Total.
type Result struct {
	Entries     []model.Entry // cuentas nuevas, listas para guardar
	Duplicates  []model.Entry // ya presentes, se ignoran
	Conflicts   []Conflict    // mismo secreto con otros datos, hay que preguntar
	Rejected    []Rejected    // no admitidas, se omiten
	Warnings    []Warning
	Batches     []Batch
	InvalidURIs []InvalidURI
	Total       int // cuentas recibidas en las URIs válidas
}

// Complete indica si se leyeron todas las URIs y no falta ningún lote.
func (r Result) Complete() bool {
	if len(r.InvalidURIs) > 0 {
		return false
	}
	for _, b := range r.Batches {
		if len(b.Missing) > 0 {
			return false
		}
	}
	return true
}

// Conflict es una cuenta con el secreto de otra pero con datos distintos.
type Conflict struct {
	Incoming model.Entry
	Existing model.Entry
}

// Rejected es una cuenta que no se puede importar.
type Rejected struct {
	Name   string
	Issuer string
	Reason string
}

// Warning avisa de algo que no impide importar. Name e Issuer están vacíos si
// no se refiere a una cuenta concreta.
type Warning struct {
	Name    string
	Issuer  string
	Message string
}

// Batch describe los QR recibidos de una exportación. Los índices empiezan en 0.
type Batch struct {
	ID       int32
	Size     int
	Received []int
	Missing  []int
	Repeated []int
}

// InvalidURI es una URI que no se pudo leer. Index es su posición en la lista
// recibida, y Err nunca cita el contenido de la URI.
type InvalidURI struct {
	Index int
	Err   error
}

// DedupeResult clasifica las cuentas recibidas frente a las existentes.
type DedupeResult struct {
	Unique     []model.Entry
	Duplicates []model.Entry
	Conflicts  []Conflict
}

// Import procesa las URIs y clasifica sus cuentas frente a las ya existentes.
// Una URI inválida o un lote incompleto no impiden importar el resto: leer el
// mismo QR otra vez solo produce duplicados, así que se puede hacer por partes.
func Import(uris []string, existing []model.Entry) Result {
	var r Result
	var incoming []model.Entry
	batches := map[int32]*Batch{}
	var order []int32

	for i, uri := range uris {
		p, err := parseURI(uri)
		if err != nil {
			r.InvalidURIs = append(r.InvalidURIs, InvalidURI{Index: i, Err: err})
			continue
		}

		b, ok := batches[p.batchID]
		if !ok {
			b = &Batch{ID: p.batchID, Size: p.batchSize}
			batches[p.batchID] = b
			order = append(order, p.batchID)
		}
		if p.batchSize != b.Size {
			r.Warnings = append(r.Warnings, Warning{
				Message: fmt.Sprintf("los QR del lote %d indican tamaños distintos", p.batchID),
			})
			b.Size = max(b.Size, p.batchSize)
		}
		if slices.Contains(b.Received, p.batchIndex) {
			b.Repeated = append(b.Repeated, p.batchIndex)
		} else {
			b.Received = append(b.Received, p.batchIndex)
		}

		r.Total += len(p.accounts)
		for _, a := range p.accounts {
			e, warnings, err := toEntry(a)
			name, issuer := normalizeName(a.name, a.issuer)
			if err != nil {
				r.Rejected = append(r.Rejected, Rejected{Name: name, Issuer: issuer, Reason: err.Error()})
				continue
			}
			for _, w := range warnings {
				r.Warnings = append(r.Warnings, Warning{Name: name, Issuer: issuer, Message: w})
			}
			incoming = append(incoming, e)
		}
	}

	for _, id := range order {
		b := batches[id]
		slices.Sort(b.Received)
		for i := range b.Size {
			if !slices.Contains(b.Received, i) {
				b.Missing = append(b.Missing, i)
			}
		}
		r.Batches = append(r.Batches, *b)
	}

	d := Dedupe(incoming, existing)
	r.Entries = d.Unique
	r.Duplicates = d.Duplicates
	r.Conflicts = d.Conflicts
	return r
}

// Dedupe compara cada cuenta recibida con las existentes y con las anteriores
// de la misma lista. El mismo secreto con los mismos datos es un duplicado; el
// mismo secreto con otros datos es un conflicto, que se comunica una sola vez.
func Dedupe(incoming, existing []model.Entry) DedupeResult {
	var d DedupeResult
	seen := slices.Clone(existing)

	for _, e := range incoming {
		var first *model.Entry
		duplicate := false
		for i := range seen {
			if !bytes.Equal(seen[i].Secret, e.Secret) {
				continue
			}
			if first == nil {
				first = &seen[i]
			}
			if sameAccount(seen[i], e) {
				duplicate = true
				break
			}
		}

		switch {
		case duplicate:
			d.Duplicates = append(d.Duplicates, e)
		case first != nil:
			d.Conflicts = append(d.Conflicts, Conflict{Incoming: e, Existing: *first})
			seen = append(seen, e)
		default:
			d.Unique = append(d.Unique, e)
			seen = append(seen, e)
		}
	}
	return d
}

func sameAccount(a, b model.Entry) bool {
	return a.Name == b.Name && a.Issuer == b.Issuer && a.Algorithm == b.Algorithm &&
		a.Digits == b.Digits && a.Period == b.Period
}

func toEntry(a account) (model.Entry, []string, error) {
	var warnings []string

	switch a.otpType {
	case typeTOTP:
	case typeHOTP:
		return model.Entry{}, nil, errors.New("las cuentas HOTP no están admitidas")
	default:
		return model.Entry{}, nil, errors.New("tipo de cuenta desconocido")
	}

	var algorithm string
	switch a.algorithm {
	case algorithmUnspecified:
		algorithm = totp.SHA1
		warnings = append(warnings, "algoritmo sin especificar: se usa SHA1")
	case algorithmSHA1:
		algorithm = totp.SHA1
	case algorithmSHA256:
		algorithm = totp.SHA256
	case algorithmSHA512:
		algorithm = totp.SHA512
	case algorithmMD5:
		return model.Entry{}, nil, errors.New("el algoritmo MD5 no está admitido")
	default:
		return model.Entry{}, nil, errors.New("algoritmo desconocido")
	}

	var digits int
	switch a.digits {
	case digitsUnspecified:
		digits = 6
		warnings = append(warnings, "dígitos sin especificar: se usan 6")
	case digitsSix:
		digits = 6
	case digitsEight:
		digits = 8
	default:
		return model.Entry{}, nil, errors.New("número de dígitos desconocido")
	}

	name, issuer := normalizeName(a.name, a.issuer)
	// El formato no incluye periodo.
	e, err := model.New(name, issuer, a.secret, algorithm, digits, model.DefaultPeriod)
	if err != nil {
		return model.Entry{}, nil, err
	}
	return e, warnings, nil
}

// normalizeName separa el emisor cuando name viene como "Emisor:cuenta". Si hay
// otro emisor explícito, name no se toca para no perder datos.
func normalizeName(name, issuer string) (string, string) {
	name = strings.TrimSpace(name)
	issuer = strings.TrimSpace(issuer)

	prefix, rest, ok := strings.Cut(name, ":")
	if !ok {
		return name, issuer
	}
	prefix = strings.TrimSpace(prefix)
	switch {
	case issuer == "":
		return strings.TrimSpace(rest), prefix
	case strings.EqualFold(prefix, issuer):
		return strings.TrimSpace(rest), issuer
	default:
		return name, issuer
	}
}
