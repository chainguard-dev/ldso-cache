package ldsocache

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

const ldsoMagic = "glibc-ld.so.cache"
const ldsoVersion = "1.1"

type LDSORawCacheHeader struct {
	Magic   [17]byte
	Version [3]byte

	NumLibs      uint32
	StrTableSize uint32

	Flags   uint8
	Unused0 [3]byte

	ExtOffset uint32

	Unused1 [3]uint32
}

type LDSORawCacheEntry struct {
	Flags uint32

	// Offsets in string table.
	Key   uint32
	Value uint32

	OSVersion_Needed uint32
	HWCap_Needed     uint64
}

type LDSOCacheEntry struct {
	Flags uint32

	Name  string

	OSVersion_Needed uint32
	HWCap_Needed     uint64
}

type LDSOCacheFile struct {
	Header  LDSORawCacheHeader
	Entries []LDSOCacheEntry
}

func (hdr *LDSORawCacheHeader) describe() {
	fmt.Printf("Header:\n")
	fmt.Printf("  Magic [%s]\n", hdr.Magic)
	fmt.Printf("  Version [%s]\n", hdr.Version)
	fmt.Printf("  %d library entries.\n", hdr.NumLibs)
	fmt.Printf("  String table is %d bytes long.\n", hdr.StrTableSize)
}

// LoadCacheFile attempts to load a cache file from disk.  When
// successful, it returns an LDSOCacheFile pointer which contains
// all relevant information from the cache file.
func LoadCacheFile(path string) (*LDSOCacheFile, error) {
	bindata, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(bindata)

	// TODO(kaniini): Use binary.BigEndian for BE targets.
	header := LDSORawCacheHeader{}
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	header.describe()

	rawlibs := []LDSORawCacheEntry{}
	for i := uint32(0); i < header.NumLibs; i++ {
		rawlib := LDSORawCacheEntry{}
		if err := binary.Read(r, binary.LittleEndian, &rawlib); err != nil {
			return nil, err
		}

		rawlibs = append(rawlibs, rawlib)
	}

	return nil, nil
}
