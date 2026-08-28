//go:build !windows

package snclient

import (
	"context"
	"fmt"
)

func (l *CheckRegistry) queryRegistry(_ context.Context) ([]registryEntry, error) {
	return nil, fmt.Errorf("check_registry is a windows only check")
}
