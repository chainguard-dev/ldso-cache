package ldsocache

import (
	"testing"
)

func Test_LoadCacheFile(t *testing.T) {
	_, err := LoadCacheFile("/etc/ld.so.cache")
	if err != nil {
		t.Fatal()
	}
}
