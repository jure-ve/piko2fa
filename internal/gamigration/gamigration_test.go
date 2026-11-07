package gamigration

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	"piko2fa/internal/model"
	"piko2fa/internal/totp"
)

// Todos los secretos de estos tests son falsos.
var fakeSecret = []byte("Hello!\xde\xad\xbe\xef")

type fakeAccount struct {
	secret            []byte
	name, issuer      string
	algorithm, digits int
	otpType           int
}

func totpAccount(secret []byte, name, issuer string) fakeAccount {
	return fakeAccount{secret, name, issuer, algorithmSHA1, digitsSix, typeTOTP}
}

// numberedSecret genera un secreto falso distinto para cada n.
func numberedSecret(n int) []byte {
	return []byte(fmt.Sprintf("secreto-falso-%06d", n))
}

func encodeAccount(a fakeAccount) []byte {
	var b []byte
	if a.secret != nil {
		b = protowire.AppendTag(b, fieldSecret, protowire.BytesType)
		b = protowire.AppendBytes(b, a.secret)
	}
	if a.name != "" {
		b = protowire.AppendTag(b, fieldName, protowire.BytesType)
		b = protowire.AppendString(b, a.name)
	}
	if a.issuer != "" {
		b = protowire.AppendTag(b, fieldIssuer, protowire.BytesType)
		b = protowire.AppendString(b, a.issuer)
	}
	// proto3 omite los ceros.
	for _, f := range []struct {
		num   protowire.Number
		value int
	}{{fieldAlgorithm, a.algorithm}, {fieldDigits, a.digits}, {fieldType, a.otpType}} {
		if f.value != 0 {
			b = protowire.AppendTag(b, f.num, protowire.VarintType)
			b = protowire.AppendVarint(b, uint64(f.value))
		}
	}
	return b
}

func encodePayload(batchID int32, index, size int, accounts ...fakeAccount) []byte {
	var b []byte
	for _, a := range accounts {
		b = protowire.AppendTag(b, fieldOTPParameters, protowire.BytesType)
		b = protowire.AppendBytes(b, encodeAccount(a))
	}
	for _, f := range []struct {
		num   protowire.Number
		value int64
	}{{2, 1}, {fieldBatchSize, int64(size)}, {fieldBatchIndex, int64(index)}, {fieldBatchID, int64(batchID)}} {
		if f.value != 0 {
			b = protowire.AppendTag(b, f.num, protowire.VarintType)
			b = protowire.AppendVarint(b, uint64(f.value))
		}
	}
	return b
}

func encodeURI(payload []byte) string {
	data := base64.StdEncoding.EncodeToString(payload)
	return "otpauth-migration://offline?data=" + url.QueryEscape(data)
}

func singleURI(accounts ...fakeAccount) string {
	return encodeURI(encodePayload(1, 0, 1, accounts...))
}

func checkCounts(t *testing.T, r Result) {
	t.Helper()
	sum := len(r.Entries) + len(r.Duplicates) + len(r.Conflicts) + len(r.Rejected)
	if sum != r.Total {
		t.Errorf("las cuentas no cuadran: %d nuevas + %d duplicadas + %d conflictos + %d rechazadas != %d recibidas",
			len(r.Entries), len(r.Duplicates), len(r.Conflicts), len(r.Rejected), r.Total)
	}
}

func TestImportSingleBatch(t *testing.T) {
	r := Import([]string{singleURI(totpAccount(fakeSecret, "usuario@example.com", "GitHub"))}, nil)
	checkCounts(t, r)

	if len(r.Entries) != 1 {
		t.Fatalf("cuentas = %d, se esperaba 1", len(r.Entries))
	}
	e := r.Entries[0]
	if e.Name != "usuario@example.com" || e.Issuer != "GitHub" || e.Algorithm != totp.SHA1 ||
		e.Digits != 6 || e.Period != 30 || e.Type != model.TypeTOTP {
		t.Errorf("campos incorrectos: %v", e)
	}
	if !bytes.Equal(e.Secret, fakeSecret) {
		t.Error("secreto incorrecto")
	}
	if !r.Complete() {
		t.Error("Complete() = false")
	}
	if len(r.Warnings) != 0 {
		t.Errorf("avisos inesperados: %v", r.Warnings)
	}
}

func TestImportMapsEnums(t *testing.T) {
	tests := []struct {
		name          string
		algorithm     int
		digits        int
		wantAlgorithm string
		wantDigits    int
		wantWarnings  int
	}{
		{"SHA1 y 6", algorithmSHA1, digitsSix, totp.SHA1, 6, 0},
		{"SHA256", algorithmSHA256, digitsSix, totp.SHA256, 6, 0},
		{"SHA512", algorithmSHA512, digitsSix, totp.SHA512, 6, 0},
		{"8 dígitos", algorithmSHA1, digitsEight, totp.SHA1, 8, 0},
		{"algoritmo a 0", algorithmUnspecified, digitsSix, totp.SHA1, 6, 1},
		{"dígitos a 0", algorithmSHA1, digitsUnspecified, totp.SHA1, 6, 1},
		{"ambos a 0", algorithmUnspecified, digitsUnspecified, totp.SHA1, 6, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := totpAccount(fakeSecret, "a", "b")
			a.algorithm, a.digits = tt.algorithm, tt.digits

			r := Import([]string{singleURI(a)}, nil)
			checkCounts(t, r)
			if len(r.Entries) != 1 {
				t.Fatalf("cuentas = %d, rechazadas = %v", len(r.Entries), r.Rejected)
			}
			if got := r.Entries[0]; got.Algorithm != tt.wantAlgorithm || got.Digits != tt.wantDigits {
				t.Errorf("Algorithm = %s, Digits = %d", got.Algorithm, got.Digits)
			}
			if len(r.Warnings) != tt.wantWarnings {
				t.Errorf("avisos = %v, se esperaban %d", r.Warnings, tt.wantWarnings)
			}
		})
	}
}

func TestImportRejectsAccountsWithoutAborting(t *testing.T) {
	tests := []struct {
		name   string
		change func(*fakeAccount)
	}{
		{"HOTP", func(a *fakeAccount) { a.otpType = typeHOTP }},
		{"tipo a 0", func(a *fakeAccount) { a.otpType = 0 }},
		{"tipo desconocido", func(a *fakeAccount) { a.otpType = 9 }},
		{"MD5", func(a *fakeAccount) { a.algorithm = algorithmMD5 }},
		{"algoritmo desconocido", func(a *fakeAccount) { a.algorithm = 9 }},
		{"dígitos desconocidos", func(a *fakeAccount) { a.digits = 9 }},
		{"sin secreto", func(a *fakeAccount) { a.secret = nil }},
		{"sin nombre ni emisor", func(a *fakeAccount) { a.name, a.issuer = "", "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bad := totpAccount(numberedSecret(1), "mala", "Emisor")
			tt.change(&bad)
			good := totpAccount(numberedSecret(2), "buena", "Emisor")

			r := Import([]string{singleURI(bad, good)}, nil)
			checkCounts(t, r)
			if len(r.Rejected) != 1 || r.Rejected[0].Reason == "" {
				t.Errorf("rechazadas = %v", r.Rejected)
			}
			if len(r.Entries) != 1 || r.Entries[0].Name != "buena" {
				t.Errorf("cuentas = %v", r.Entries)
			}
		})
	}
}

func TestImportNormalizesNames(t *testing.T) {
	tests := []struct {
		name, account, issuer string
		wantName, wantIssuer  string
	}{
		{"sin prefijo", "usuario", "GitHub", "usuario", "GitHub"},
		{"prefijo igual al emisor", "GitHub:usuario", "GitHub", "usuario", "GitHub"},
		{"prefijo con otras mayúsculas", "github:usuario", "GitHub", "usuario", "GitHub"},
		{"prefijo con espacios", "GitHub: usuario", "GitHub", "usuario", "GitHub"},
		{"prefijo sin emisor", "GitHub:usuario", "", "usuario", "GitHub"},
		{"prefijo distinto: se conserva", "Otro:usuario", "GitHub", "Otro:usuario", "GitHub"},
		{"solo emisor en el nombre", "GitHub:", "GitHub", "", "GitHub"},
		{"espacios alrededor", "  usuario ", " GitHub ", "usuario", "GitHub"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Import([]string{singleURI(totpAccount(fakeSecret, tt.account, tt.issuer))}, nil)
			if len(r.Entries) != 1 {
				t.Fatalf("cuentas = %d, rechazadas = %v", len(r.Entries), r.Rejected)
			}
			if got := r.Entries[0]; got.Name != tt.wantName || got.Issuer != tt.wantIssuer {
				t.Errorf("Name = %q, Issuer = %q", got.Name, got.Issuer)
			}
		})
	}
}

// El base64 de este payload contiene "+" y "/", que una segunda decodificación
// de la URL corrompería.
func payloadWithPlusAndSlash(t *testing.T) ([]byte, string) {
	t.Helper()
	pattern := []byte{0xfb, 0xef, 0xbe, 0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	for pad := range 3 {
		secret := append(make([]byte, pad), pattern...)
		data := base64.StdEncoding.EncodeToString(encodePayload(1, 0, 1, totpAccount(secret, "a", "b")))
		if strings.Contains(data, "+") && strings.Contains(data, "/") {
			return secret, data
		}
	}
	t.Fatal("no se obtuvo un base64 con + y /")
	return nil, ""
}

func TestImportDecodesBase64Variants(t *testing.T) {
	secret, data := payloadWithPlusAndSlash(t)
	const prefix = "otpauth-migration://offline?data="

	tests := []struct{ name, uri string }{
		{"codificado", prefix + url.QueryEscape(data)},
		{"+ sin codificar", prefix + data},
		{"sin relleno", prefix + url.QueryEscape(strings.TrimRight(data, "="))},
		{"+ convertido en espacio", prefix + strings.ReplaceAll(url.QueryEscape(data), "%2B", "%20")},
		{"espacios alrededor", "  " + prefix + url.QueryEscape(data) + "\n"},
		{"mayúsculas en esquema y host", "OTPAUTH-MIGRATION://OFFLINE?data=" + url.QueryEscape(data)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Import([]string{tt.uri}, nil)
			if len(r.InvalidURIs) != 0 {
				t.Fatalf("URI rechazada: %v", r.InvalidURIs[0].Err)
			}
			if len(r.Entries) != 1 || !bytes.Equal(r.Entries[0].Secret, secret) {
				t.Error("secreto incorrecto")
			}
		})
	}
}

func TestImportReportsInvalidURIsAndContinues(t *testing.T) {
	good := singleURI(totpAccount(fakeSecret, "a", "b"))
	valid := encodePayload(1, 0, 1, totpAccount(fakeSecret, "a", "b"))
	const prefix = "otpauth-migration://offline?data="

	truncatedField := protowire.AppendTag(nil, fieldOTPParameters, protowire.BytesType)
	truncatedField = protowire.AppendVarint(truncatedField, 50)

	wrongWireType := protowire.AppendTag(nil, fieldOTPParameters, protowire.VarintType)
	wrongWireType = protowire.AppendVarint(wrongWireType, 1)

	wrongBatchWireType := protowire.AppendTag(valid[:len(valid):len(valid)], fieldBatchSize, protowire.BytesType)
	wrongBatchWireType = protowire.AppendString(wrongBatchWireType, "x")

	invalidName := protowire.AppendTag(nil, fieldName, protowire.BytesType)
	invalidName = protowire.AppendBytes(invalidName, []byte{0xff, 0xfe})
	invalidUTF8 := protowire.AppendTag(nil, fieldOTPParameters, protowire.BytesType)
	invalidUTF8 = protowire.AppendBytes(invalidUTF8, invalidName)

	truncatedAccount := protowire.AppendTag(nil, fieldOTPParameters, protowire.BytesType)
	truncatedAccount = protowire.AppendBytes(truncatedAccount, []byte{0x0a, 0x50})

	tests := []struct{ name, uri string }{
		{"vacía", ""},
		{"otro esquema", "https://offline?data=AAAA"},
		{"otro host", "otpauth-migration://online?data=" + url.QueryEscape(base64.StdEncoding.EncodeToString(valid))},
		{"URI otpauth normal", "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP"},
		{"sin data", "otpauth-migration://offline"},
		{"data repetido", prefix + "AAAA&data=AAAA"},
		{"escape incorrecto", prefix + "%zz"},
		{"base64 inválido", prefix + "no-es-base64!"},
		{"base64 de URL segura", prefix + "__--"},
		{"data vacío", prefix},
		{"protobuf truncado", encodeURI(valid[:len(valid)-1])},
		{"etiqueta inválida", encodeURI([]byte{0x80})},
		{"longitud mayor que los datos", encodeURI(truncatedField)},
		{"tipo de cable incorrecto en cuentas", encodeURI(wrongWireType)},
		{"tipo de cable incorrecto en lote", encodeURI(wrongBatchWireType)},
		{"cuenta truncada", encodeURI(truncatedAccount)},
		{"nombre con UTF-8 inválido", encodeURI(invalidUTF8)},
		{"sin cuentas", encodeURI(encodePayload(1, 0, 1))},
		{"índice igual al tamaño", encodeURI(encodePayload(1, 2, 2, totpAccount(fakeSecret, "a", "b")))},
		{"índice negativo", encodeURI(encodePayload(1, -1, 2, totpAccount(fakeSecret, "a", "b")))},
		{"tamaño negativo", encodeURI(encodePayload(1, 0, -2, totpAccount(fakeSecret, "a", "b")))},
		{"tamaño excesivo", encodeURI(encodePayload(1, 0, 2_000_000_000, totpAccount(fakeSecret, "a", "b")))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Import([]string{good, tt.uri}, nil)
			checkCounts(t, r)
			if len(r.InvalidURIs) != 1 {
				t.Fatalf("URIs inválidas = %d, se esperaba 1", len(r.InvalidURIs))
			}
			if r.InvalidURIs[0].Index != 1 {
				t.Errorf("Index = %d, se esperaba 1", r.InvalidURIs[0].Index)
			}
			if len(r.Entries) != 1 {
				t.Errorf("cuentas = %d: la URI válida debe importarse igualmente", len(r.Entries))
			}
			if r.Complete() {
				t.Error("Complete() = true con una URI inválida")
			}
		})
	}
}

func TestImportSkipsUnknownFields(t *testing.T) {
	account := encodeAccount(totpAccount(fakeSecret, "a", "b"))
	account = protowire.AppendTag(account, 7, protowire.VarintType) // counter
	account = protowire.AppendVarint(account, 5)
	account = protowire.AppendTag(account, 99, protowire.BytesType)
	account = protowire.AppendString(account, "futuro")

	var b []byte
	b = protowire.AppendTag(b, fieldOTPParameters, protowire.BytesType)
	b = protowire.AppendBytes(b, account)
	b = protowire.AppendTag(b, 99, protowire.Fixed32Type)
	b = protowire.AppendFixed32(b, 1)

	r := Import([]string{encodeURI(b)}, nil)
	if len(r.InvalidURIs) != 0 {
		t.Fatalf("URI rechazada: %v", r.InvalidURIs[0].Err)
	}
	if len(r.Entries) != 1 {
		t.Errorf("cuentas = %d, se esperaba 1", len(r.Entries))
	}
}

// Criterio de aceptación: varios lotes, en cualquier orden, recuperan todas las
// cuentas exactamente una vez.
func TestImportManyBatchesRecoversEveryAccountOnce(t *testing.T) {
	const accounts, perBatch = 287, 10
	const size = (accounts + perBatch - 1) / perBatch

	var uris []string
	for index := range size {
		var batch []fakeAccount
		for i := index * perBatch; i < min((index+1)*perBatch, accounts); i++ {
			batch = append(batch, totpAccount(numberedSecret(i), fmt.Sprintf("usuario%d", i), "Emisor"))
		}
		uris = append(uris, encodeURI(encodePayload(-12345, index, size, batch...)))
	}
	slices.Reverse(uris)

	r := Import(uris, nil)
	checkCounts(t, r)
	if !r.Complete() {
		t.Errorf("Complete() = false; lotes = %v", r.Batches)
	}
	if r.Total != accounts || len(r.Entries) != accounts {
		t.Fatalf("Total = %d, cuentas = %d, se esperaban %d", r.Total, len(r.Entries), accounts)
	}
	for i := range accounts {
		name := fmt.Sprintf("usuario%d", i)
		matches := 0
		for _, e := range r.Entries {
			if e.Name == name && bytes.Equal(e.Secret, numberedSecret(i)) {
				matches++
			}
		}
		if matches != 1 {
			t.Errorf("%s aparece %d veces", name, matches)
		}
	}
	if len(r.Batches) != 1 || r.Batches[0].ID != -12345 || r.Batches[0].Size != size {
		t.Errorf("lotes = %v", r.Batches)
	}
}

func TestImportReportsMissingBatches(t *testing.T) {
	uris := []string{
		encodeURI(encodePayload(7, 2, 4, totpAccount(numberedSecret(2), "c", "E"))),
		encodeURI(encodePayload(7, 0, 4, totpAccount(numberedSecret(0), "a", "E"))),
	}

	r := Import(uris, nil)
	checkCounts(t, r)
	if r.Complete() {
		t.Error("Complete() = true con lotes faltantes")
	}
	if len(r.Entries) != 2 {
		t.Errorf("cuentas = %d: lo recibido debe poder importarse", len(r.Entries))
	}
	b := r.Batches[0]
	if !slices.Equal(b.Missing, []int{1, 3}) {
		t.Errorf("Missing = %v, se esperaba [1 3]", b.Missing)
	}
	if !slices.Equal(b.Received, []int{0, 2}) {
		t.Errorf("Received = %v, se esperaba [0 2]", b.Received)
	}
}

func TestImportToleratesRepeatedQR(t *testing.T) {
	first := encodeURI(encodePayload(7, 0, 2, totpAccount(numberedSecret(0), "a", "E")))
	second := encodeURI(encodePayload(7, 1, 2, totpAccount(numberedSecret(1), "b", "E")))

	r := Import([]string{first, second, first}, nil)
	checkCounts(t, r)
	if !r.Complete() {
		t.Error("Complete() = false")
	}
	if len(r.Entries) != 2 || len(r.Duplicates) != 1 {
		t.Errorf("cuentas = %d, duplicadas = %d", len(r.Entries), len(r.Duplicates))
	}
	if !slices.Equal(r.Batches[0].Repeated, []int{0}) {
		t.Errorf("Repeated = %v, se esperaba [0]", r.Batches[0].Repeated)
	}
}

// Importar por partes contra lo ya guardado no debe crear cuentas repetidas.
func TestImportInPartsIsIdempotent(t *testing.T) {
	first := encodeURI(encodePayload(7, 0, 2, totpAccount(numberedSecret(0), "a", "E")))
	second := encodeURI(encodePayload(7, 1, 2, totpAccount(numberedSecret(1), "b", "E")))

	part1 := Import([]string{first}, nil)
	part2 := Import([]string{first, second}, part1.Entries)
	checkCounts(t, part2)

	if len(part2.Entries) != 1 || part2.Entries[0].Name != "b" {
		t.Errorf("cuentas nuevas = %v", part2.Entries)
	}
	if len(part2.Duplicates) != 1 {
		t.Errorf("duplicadas = %d, se esperaba 1", len(part2.Duplicates))
	}
}

func TestImportSeparatesExports(t *testing.T) {
	uris := []string{
		encodeURI(encodePayload(1, 0, 2, totpAccount(numberedSecret(0), "a", "E"))),
		encodeURI(encodePayload(2, 0, 1, totpAccount(numberedSecret(1), "b", "E"))),
	}

	r := Import(uris, nil)
	if len(r.Batches) != 2 {
		t.Fatalf("lotes = %d, se esperaban 2", len(r.Batches))
	}
	if !slices.Equal(r.Batches[0].Missing, []int{1}) || len(r.Batches[1].Missing) != 0 {
		t.Errorf("lotes = %v", r.Batches)
	}
}

func TestImportTreatsMissingBatchFieldsAsSingleQR(t *testing.T) {
	r := Import([]string{encodeURI(encodePayload(0, 0, 0, totpAccount(fakeSecret, "a", "b")))}, nil)
	checkCounts(t, r)
	if !r.Complete() || len(r.Entries) != 1 {
		t.Errorf("Complete() = %v, cuentas = %d", r.Complete(), len(r.Entries))
	}
	if r.Batches[0].Size != 1 {
		t.Errorf("Size = %d, se esperaba 1", r.Batches[0].Size)
	}
}

func TestImportWarnsAboutInconsistentBatchSize(t *testing.T) {
	uris := []string{
		encodeURI(encodePayload(7, 0, 2, totpAccount(numberedSecret(0), "a", "E"))),
		encodeURI(encodePayload(7, 1, 3, totpAccount(numberedSecret(1), "b", "E"))),
	}

	r := Import(uris, nil)
	if len(r.Warnings) != 1 {
		t.Errorf("avisos = %v, se esperaba 1", r.Warnings)
	}
	if r.Batches[0].Size != 3 || !slices.Equal(r.Batches[0].Missing, []int{2}) {
		t.Errorf("lote = %+v", r.Batches[0])
	}
}

func newEntry(t *testing.T, secret []byte, name, issuer string) model.Entry {
	t.Helper()
	e, err := model.New(name, issuer, secret, totp.SHA1, 6, 30)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestDedupe(t *testing.T) {
	s1, s2 := numberedSecret(1), numberedSecret(2)
	existing := []model.Entry{newEntry(t, s1, "a", "E")}

	otherDigits := newEntry(t, s1, "a", "E")
	otherDigits.Digits = 8

	tests := []struct {
		name                                      string
		incoming                                  []model.Entry
		wantUnique, wantDuplicates, wantConflicts int
	}{
		{"nueva", []model.Entry{newEntry(t, s2, "b", "E")}, 1, 0, 0},
		{"igual que una existente", []model.Entry{newEntry(t, s1, "a", "E")}, 0, 1, 0},
		{"mismo secreto, otro nombre", []model.Entry{newEntry(t, s1, "otro", "E")}, 0, 0, 1},
		{"mismo secreto, otro emisor", []model.Entry{newEntry(t, s1, "a", "Otro")}, 0, 0, 1},
		{"mismo secreto, otros dígitos", []model.Entry{otherDigits}, 0, 0, 1},
		{"mismo nombre, otro secreto", []model.Entry{newEntry(t, s2, "a", "E")}, 1, 0, 0},
		{"repetida en la lista", []model.Entry{newEntry(t, s2, "b", "E"), newEntry(t, s2, "b", "E")}, 1, 1, 0},
		{"conflicto dentro de la lista", []model.Entry{newEntry(t, s2, "b", "E"), newEntry(t, s2, "c", "E")}, 1, 0, 1},
		{"conflicto repetido se comunica una vez", []model.Entry{newEntry(t, s1, "otro", "E"), newEntry(t, s1, "otro", "E")}, 0, 1, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Dedupe(tt.incoming, existing)
			if len(d.Unique) != tt.wantUnique || len(d.Duplicates) != tt.wantDuplicates || len(d.Conflicts) != tt.wantConflicts {
				t.Errorf("nuevas = %d, duplicadas = %d, conflictos = %d; se esperaban %d, %d, %d",
					len(d.Unique), len(d.Duplicates), len(d.Conflicts), tt.wantUnique, tt.wantDuplicates, tt.wantConflicts)
			}
		})
	}
}

func TestDedupeConflictNamesExistingAccount(t *testing.T) {
	existing := newEntry(t, fakeSecret, "a", "E")
	incoming := newEntry(t, fakeSecret, "otro", "E")

	d := Dedupe([]model.Entry{incoming}, []model.Entry{existing})
	if len(d.Conflicts) != 1 {
		t.Fatalf("conflictos = %d, se esperaba 1", len(d.Conflicts))
	}
	if d.Conflicts[0].Existing.ID != existing.ID || d.Conflicts[0].Incoming.ID != incoming.ID {
		t.Errorf("conflicto incorrecto: %v", d.Conflicts[0])
	}
}

func TestDedupeDoesNotModifyExisting(t *testing.T) {
	existing := make([]model.Entry, 1, 10)
	existing[0] = newEntry(t, numberedSecret(1), "a", "E")

	Dedupe([]model.Entry{newEntry(t, numberedSecret(2), "b", "E")}, existing)

	if extra := existing[:2][1]; extra.ID != "" {
		t.Error("Dedupe escribió en el arreglo recibido")
	}
}

func TestErrorsAndPrintingDoNotLeakSecrets(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	const prefix = "otpauth-migration://offline"

	uris := []string{
		prefix + "%zz?data=" + secret,
		"1" + prefix + "?data=" + secret,
		prefix + "?data=" + secret + "!",
		prefix + "?data=" + secret + "&x=%zz",
		prefix + "?data=" + secret + ";x=1",
		"https://offline?data=" + secret,
		singleURI(totpAccount(fakeSecret, "a", "b")),
		singleURI(fakeAccount{secret: fakeSecret, name: "mala", otpType: typeHOTP}),
	}

	r := Import(uris, []model.Entry{newEntry(t, fakeSecret, "otro", "E")})
	if len(r.InvalidURIs) != 6 {
		t.Fatalf("URIs inválidas = %d, se esperaban 6", len(r.InvalidURIs))
	}
	for _, invalid := range r.InvalidURIs {
		if strings.Contains(invalid.Err.Error(), secret) {
			t.Errorf("el error muestra el secreto: %v", invalid.Err)
		}
	}

	out := fmt.Sprintf("%v %+v", r, r)
	if strings.Contains(out, "Hello") || strings.Contains(out, "72 101") {
		t.Errorf("el resultado muestra el secreto: %s", out)
	}
}
