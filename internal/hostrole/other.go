//go:build !windows

package hostrole

import (
	"context"
	"errors"
)

// ErrUnsupported is returned on platforms without a facts probe. The
// hostrole.v1 collector advertises Windows only, so this is a guard rather
// than an expected job outcome.
var ErrUnsupported = errors.New("host role detection is implemented on Windows only")

type unsupportedSource struct{}

// NewSource returns a source that reports ErrUnsupported.
func NewSource() Source { return unsupportedSource{} }

func (unsupportedSource) Facts(ctx context.Context) (*Facts, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}
