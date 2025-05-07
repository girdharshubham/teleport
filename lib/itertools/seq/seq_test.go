package seq

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSlice tests the Slice function.
func TestSlice(t *testing.T) {
	tests := []struct {
		name   string
		input  []int
		output []int
	}{
		{
			name:   "nil",
			input:  nil,
			output: nil,
		},
		{
			name:   "empty",
			input:  []int{},
			output: nil,
		},
		{
			name:   "single element",
			input:  []int{1},
			output: []int{1},
		},
		{
			name:   "multiple elements",
			input:  []int{1, 2, 3},
			output: []int{1, 2, 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.output, Collect(Slice(tt.input)))
		})
	}
}
