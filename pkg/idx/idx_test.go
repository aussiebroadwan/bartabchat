package idx_test

import (
	"testing"
	"time"

	"github.com/aussiebroadwan/bartab/pkg/idx"
	"github.com/stretchr/testify/require"
)

func TestNewAndParse(t *testing.T) {
	id := idx.New()

	// I should really use MustNew instead, but I am curious if this breaks at
	// anypoint MustNew is mainly there for assurance.
	require.NotEmpty(t, id.String())

	// Parse a newly generated string
	parsed, err := idx.Parse(id.String())

	// Validate State
	require.NoError(t, err)
	require.Equal(t, id, parsed)
	require.False(t, id.IsZero())
}

func TestOrdering(t *testing.T) {
	a := idx.NewAt(time.Unix(1, 0).UTC())
	b := idx.NewAt(time.Unix(2, 0).UTC())

	// Check valid comparisons, I usually always get this wrong
	require.Equal(t, -1, idx.Compare(a, b))
	require.Equal(t, 1, idx.Compare(b, a))
	require.Equal(t, 0, idx.Compare(a, a))
}

func TestTimeExtraction(t *testing.T) {
	tm := time.Unix(1700000000, 0).UTC()
	id := idx.NewAt(tm)

	// Check if we get the right time out, I'm not sure how well the resolution
	require.WithinDuration(t, tm, id.Time(), time.Millisecond)
}

func TestMustParse(t *testing.T) {

	// This will panic if it fails, I could create a recover harness to have
	// a proper test but I'm being lazy
	id := idx.MustParse("01HQ7T3Z1MZ0JQ3M6MZQ1FQ3ZV") // any valid ULID
	_ = id
}
