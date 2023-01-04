// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ldsocache

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"
)

const ldsoMagic = "glibc-ld.so.cache"
const ldsoVersion = "1.1"
const ldsoExtensionMagic = 0xEAA42174
const cacheExtensionTagGenerator = uint32(1)

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

	Name string

	OSVersion_Needed uint32
	HWCap_Needed     uint64
}

type LDSOCacheExtensionHeader struct {
	Magic uint32
	Count uint32
}

type LDSOCacheExtensionSectionHeader struct {
	Tag    uint32
	Flags  uint32
	Offset uint32
	Size   uint32
}

type LDSOCacheExtensionSection struct {
	Header LDSOCacheExtensionSectionHeader
	Data   []byte
}

type LDSOCacheFile struct {
	Header     LDSORawCacheHeader
	Entries    []LDSOCacheEntry
	Extensions []LDSOCacheExtensionSection
}

func (hdr *LDSORawCacheHeader) describe() {
	fmt.Printf("Header:\n")
	fmt.Printf("  Magic [%s]\n", hdr.Magic)
	fmt.Printf("  Version [%s]\n", hdr.Version)
	fmt.Printf("  %d library entries.\n", hdr.NumLibs)
	fmt.Printf("  String table is %d bytes long.\n", hdr.StrTableSize)
}

func (ehdr *LDSOCacheExtensionHeader) describe() {
	fmt.Printf("Extension header:\n")
	fmt.Printf("  %d entries.\n", ehdr.Count)
}

func (shdr *LDSOCacheExtensionSectionHeader) describe() {
	fmt.Printf("Extension section header:\n")
	fmt.Printf("  Tag [%d]\n", shdr.Tag)
	fmt.Printf("  Flags [%x]\n", shdr.Flags)
	fmt.Printf("  Offset [%d]\n", shdr.Offset)
	fmt.Printf("  Size [%d]\n", shdr.Size)
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

	pos, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	// The string table is a series of nul-terminated C strings.
	strtable := make([]byte, header.StrTableSize)
	if _, err := r.Read(strtable); err != nil {
		return nil, err
	}

	// Now build the cache index itself.
	entries := []LDSOCacheEntry{}
	for _, rawlib := range rawlibs {
		entry := LDSOCacheEntry{
			Flags:            rawlib.Flags,
			OSVersion_Needed: rawlib.OSVersion_Needed,
			HWCap_Needed:     rawlib.HWCap_Needed,
		}

		name, err := extractShlibName(strtable, rawlib.Value-uint32(pos))
		if err != nil {
			return nil, err
		}

		entry.Name = name

		entries = append(entries, entry)
	}

	// Extension data begins at the next 4-byte aligned position.
	pos, err = r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	// Align to nearest 4 byte boundary.
	alignedPos := (pos & -16) + 8
	pos, err = r.Seek(alignedPos, io.SeekStart)
	if err != nil {
		return nil, err
	}

	file := LDSOCacheFile{
		Header:  header,
		Entries: entries,
	}

	// Check for a cache extension section.
	extHeader := LDSOCacheExtensionHeader{}
	if err := binary.Read(r, binary.LittleEndian, &extHeader); err != nil {
		return &file, nil
	}
	if extHeader.Magic != ldsoExtensionMagic {
		return &file, nil
	}
	extHeader.describe()

	// Parse the extension chunks we understand.
	sections := []*LDSOCacheExtensionSection{}
	for i := uint32(0); i < extHeader.Count; i++ {
		sectionHeader := LDSOCacheExtensionSectionHeader{}
		if err := binary.Read(r, binary.LittleEndian, &sectionHeader); err != nil {
			return &file, nil
		}
		sectionHeader.describe()

		section := &LDSOCacheExtensionSection{Header: sectionHeader}
		sections = append(sections, section)
	}

	// Load extension data.
	for _, section := range sections {
		pos, err = r.Seek(int64(section.Header.Offset), io.SeekStart)
		if err != nil {
			return &file, nil
		}
		if pos != int64(section.Header.Offset) {
			return &file, nil
		}

		section.Data = make([]byte, section.Header.Size)
		if _, err := r.Read(section.Data); err != nil {
			return &file, nil
		}
	}

	for _, section := range sections {
		file.Extensions = append(file.Extensions, *section)
	}

	return &file, nil
}

// extractShlibName extracts a shared library from the string table.
func extractShlibName(strtable []byte, startIdx uint32) (string, error) {
	subset := strtable[startIdx:]
	terminatorPos := bytes.IndexByte(subset, 0x0)

	if terminatorPos == -1 {
		return string(subset), nil
	}

	return string(subset[:terminatorPos]), nil
}

// Write writes a cache file to disk.
func (cf *LDSOCacheFile) Write(path string) error {
	buf := &bytes.Buffer{}

	// Calculate the size of the file entry table for use
	// when calculating the file entry string table offsets.
	fileEntryTableSize := int(unsafe.Sizeof(LDSORawCacheHeader{}) + (uintptr(len(cf.Entries)) * unsafe.Sizeof(LDSORawCacheEntry{})))

	// Write the header section.
	if err := cf.Header.Write(buf); err != nil {
		return err
	}

	// Build the string table.
	lrcEntries := []LDSORawCacheEntry{}
	stringTable := []byte{}
	for _, lib := range cf.Entries {
		cursor := uint32(fileEntryTableSize) + uint32(len(stringTable))
		entry := []byte(lib.Name)
		entry = append(entry, byte(0x0))
		stringTable = append(stringTable, entry...)

		lrcEntry := LDSORawCacheEntry{
			Flags: lib.Flags,
			Key: cursor + uint32(len(filepath.Dir(lib.Name))),
			Value: cursor,
			OSVersion_Needed: lib.OSVersion_Needed,
			HWCap_Needed: lib.HWCap_Needed,
		}

		lrcEntries = append(lrcEntries, lrcEntry)
	}

	// Write the file entry table.
	if err := binary.Write(buf, binary.LittleEndian, &lrcEntries); err != nil {
		return err
	}

	// Write the string table.
	if _, err := buf.Write(stringTable); err != nil {
		return err
	}

	pos := buf.Len()
	fmt.Printf("pos = %d\n", pos)

	alignedPos := (pos & -16) + 8
	fmt.Printf("aligned = %d\n", alignedPos)

	pad := make([]byte, alignedPos - pos)
	if _, err := buf.Write(pad); err != nil {
		return err
	}

	// Write the extension sections.
	if len(cf.Extensions) > 0 {
		ehdr := LDSOCacheExtensionHeader{
			Magic: ldsoExtensionMagic,
			Count: uint32(len(cf.Extensions)),
		}

		if err := binary.Write(buf, binary.LittleEndian, &ehdr); err != nil {
			return err
		}

		for _, ext := range cf.Extensions {
			if err := binary.Write(buf, binary.LittleEndian, ext.Header); err != nil {
				return err
			}
		}

		for _, ext := range cf.Extensions {
			if _, err := buf.Write(ext.Data); err != nil {
				return err
			}
		}
	}

	w, err := os.Create(path)
	if err != nil {
		return err
	}
	defer w.Close()

	if _, err := io.Copy(w, buf); err != nil {
		return err
	}

	return nil
}

// Write writes a header for a cache file to disk.
func (hdr *LDSORawCacheHeader) Write(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, hdr); err != nil {
		return err
	}

	return nil
}
