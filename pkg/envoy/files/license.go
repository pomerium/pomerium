package files

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrNoLicenseFound = errors.New("no license found")
	readLicenseIDOnce = sync.OnceValues(func() (string, error) {
		raw := Binary()
		if len(raw) < 4 {
			return "", errors.New("no embedded binary")
		}
		if bytes.HasPrefix(raw, []byte(elf.ELFMAG)) {
			return embeddedEnvoyLicenseIdentifierELF(raw)
		}
		return embeddedEnvoyLicenseIdentifierMachO(raw)
	})
)

func EmbeddedEnvoyLicenseIdentifier() (string, error) {
	return readLicenseIDOnce()
}

func EmbeddedEnvoyLicenseIdentifierOrError() string {
	license, err := EmbeddedEnvoyLicenseIdentifier()
	if err != nil {
		return err.Error()
	}
	return license
}

func embeddedEnvoyLicenseIdentifierELF(raw []byte) (string, error) {
	f := bytes.NewReader(raw)
	ef, err := elf.NewFile(f)
	if err != nil {
		return "", fmt.Errorf("error reading embedded binary: %w", err)
	}
	defer ef.Close()

	var section *elf.Section
	sectionIdx := -1
	for i, s := range ef.Sections[:len(ef.Sections)-1] {
		if s.Name == ".license" {
			section = s
			sectionIdx = i
			break
		}
	}
	if section == nil {
		return "", ErrNoLicenseFound
	}

	if !validateSection(section.Addr, section.Size,
		ef.Sections[sectionIdx+1].Addr, ef.Sections[sectionIdx+1].Addralign) {
		return "", fmt.Errorf("error reading embedded binary: version data is malformed")
	}
	data, err := section.Data()
	if err != nil {
		return "", fmt.Errorf("error reading embedded binary: %w", err)
	}
	if data[len(data)-1] != 0 { // should be a null terminated string
		return "", fmt.Errorf("error reading embedded binary: version data is malformed")
	}
	str := string(data[:len(data)-1])
	return str, nil
}

func embeddedEnvoyLicenseIdentifierMachO(raw []byte) (string, error) {
	f := bytes.NewReader(raw)
	// TODO: this is much slower than elf.NewFile and reads a lot of superflous
	// data. For the smaller release binaries it takes ~200-300ms which is maybe
	// reasonable but could slow down integration tests.
	ef, err := macho.NewFile(f)
	if err != nil {
		return "", fmt.Errorf("error reading embedded binary: %w", err)
	}
	defer ef.Close()

	var section *macho.Section
	sectionIdx := -1
	for i, s := range ef.Sections[:len(ef.Sections)-1] {
		if s.Seg == "__TEXT" && s.Name == "__license" {
			section = s
			sectionIdx = i
			break
		}
	}
	if section == nil {
		return "", ErrNoLicenseFound
	}

	if !validateSection(section.Addr, section.Size,
		ef.Sections[sectionIdx+1].Addr, uint64(1)<<ef.Sections[sectionIdx+1].Align) {
		return "", fmt.Errorf("error reading embedded binary: version data is malformed")
	}
	data, err := section.Data()
	if err != nil {
		return "", fmt.Errorf("error reading embedded binary: %w", err)
	}
	if data[len(data)-1] != 0 { // should be a null terminated string
		return "", fmt.Errorf("error reading embedded binary: version data is malformed")
	}
	str := string(data[:len(data)-1])
	return str, nil
}

func validateSection(addr uint64, size uint64, nextAddr uint64, nextAlign uint64) bool {
	return size < 256 && // arbitrary limit
		((addr+size+nextAlign-1)&^(nextAlign-1) == nextAddr) // check section alignment
}
