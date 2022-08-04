//nolint:gochecknoinits
package cachedconstants

import "os"

//nolint:gochecknoglobals
var (
	pageSize int
)

func init() {
	pageSize = os.Getpagesize()
	if pageSize == 0 {
		pageSize = 4096
	}
}

// PageSize returns the OS page size value as determined at initial module load.
func PageSize() int {
	return pageSize
}
