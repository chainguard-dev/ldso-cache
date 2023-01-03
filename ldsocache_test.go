package ldsocache

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_LoadCacheFile(t *testing.T) {
	cacheFile, err := LoadCacheFile("testdata/ld.so.cache")
	require.NoError(t, err)
	require.Equalf(t, uint32(65), cacheFile.Header.NumLibs, "there should be 65 libraries in this cache file")
	require.Equalf(t, uint32(1421), cacheFile.Header.StrTableSize, "the string table should be 1421 bytes long")
}
