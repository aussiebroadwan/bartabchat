package idx

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

type ID string

// Zero represents the zero value ID, don't use this unless its a placeholder.
const Zero ID = ""

const ULIDSizeBytes = 16

// ErrInvalid reports a malformed ULID string.
var ErrInvalid = errors.New("idx: invalid ulid")

var (
	globalOnce sync.Once
	global     *generator
)

// generator is a tool to safely generate ULIDs concurrently using a monotonic
// source.
type generator struct {
	mu      sync.Mutex
	entropy *ulid.MonotonicEntropy
}

func (g *generator) New() ID {
	return g.NewAt(time.Now().UTC())
}

func (g *generator) NewAt(t time.Time) ID {
	g.mu.Lock()
	defer g.mu.Unlock()

	u := ulid.MustNew(ulid.Timestamp(t), g.entropy)
	return ID(u.String())
}

func initGlobal() {
	src := ulid.Monotonic(rand.Reader, 0) // Max Monotonic Window
	global = &generator{entropy: src}
}

// New returns a new lexicographically sortable ULID-based ID using the
// current time in UTC and a monotonic entropy source.
func New() ID {
	globalOnce.Do(initGlobal)
	return global.New()
}

// MustNew is like New but panics on unexpected failure (extremely unlikely).
func MustNew() ID {
	id := New()
	if id == Zero {
		// Panic here so we don't put the program into an unknown state
		panic("idx: failred to generate ULID")
	}

	return id
}

// NewAt generates an ID at the provided time (UTC), useful for tests or
// constructing time-bounded cursors.
func NewAt(t time.Time) ID {
	globalOnce.Do(initGlobal)
	return global.NewAt(t)
}

// Parse parses a ULID string into an ID and validates its form.
func Parse(s string) (ID, error) {
	s = strings.TrimSpace(s)

	// Check simple valid string
	if s == "" {
		return Zero, ErrInvalid
	}

	// Parse the string properly
	if _, err := ulid.ParseStrict(s); err != nil {
		return Zero, ErrInvalid
	}

	return ID(s), nil
}

// MustParse parses or panics. Useful for hard-coded IDs in tests.
func MustParse(s string) ID {
	id, err := Parse(s)
	if err != nil {
		// Panic here so we don't put the program into an unknown state
		panic(err)
	}
	return id
}

// IsZero reports whether id is the zero value.
func (id ID) IsZero() bool { return id == Zero }

// String returns the canonical string form.
func (id ID) String() string { return string(id) }

// Bytes returns the 16-byte ULID representation or nil for zero IDs.
func (id ID) Bytes() []byte {
	if id.IsZero() {
		return nil
	}

	u, err := ulid.ParseStrict(id.String())
	if err != nil {
		return nil
	}

	b := make([]byte, ULIDSizeBytes)
	_ = u.MarshalBinaryTo(b)
	return b
}

// Time extracts the embedded UTC timestamp from the ID.
// If the ID is invalid or zero, it returns the zero time.
func (id ID) Time() time.Time {
	if id.IsZero() {
		return time.Time{}
	}

	u, err := ulid.ParseStrict(id.String())
	if err != nil {
		return time.Time{}
	}

	// ULID time component is in ms since epoch.
	return ulid.Time(u.Time())
}

// Compare reports the lexical ordering between a and b.
// Returns -1 if a<b, 0 if a==b, +1 if a>b.
// Zero or invalid IDs compare using simple string compare.
func Compare(a, b ID) int {
	as := a.String()
	bs := b.String()

	switch {
	case as < bs:
		return -1
	case as > bs:
		return 1
	default:
		return 0
	}
}

// EncodeBase32Lower encodes raw 16-byte ULID data using Crockford base32
// in lowercase. This is rarely needed—String() already returns canonical form.
func EncodeBase32Lower(b []byte) string {
	enc := base32.NewEncoding("0123456789abcdefghjkmnpqrstuvwxyz").WithPadding(base32.NoPadding)
	return enc.EncodeToString(b)
}
