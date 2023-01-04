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
	require.Equalf(t, 1, len(cacheFile.Extensions), "there must be 1 extension")

	ext := cacheFile.Extensions[0]
	require.Equalf(t, uint32(0), ext.Header.Tag, "extension data must be tag 0 (generator)")
	require.Equalf(t, []byte("ldconfig (GNU libc) stable release version 2.36"), ext.Data, "must be generated by glibc 2.36")
}
