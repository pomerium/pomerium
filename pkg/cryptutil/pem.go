package cryptutil

import (
	"bytes"
	"cmp"
	"crypto/x509"
	"encoding/pem"
	"iter"
	"slices"

	"github.com/hashicorp/go-set/v3"
)

type signedCertificateIndex struct {
	idToAuthorityKey map[int]string
	subjectKeyToID   map[string]int
}

func newSignedCertificateIndex() *signedCertificateIndex {
	return &signedCertificateIndex{
		idToAuthorityKey: make(map[int]string),
		subjectKeyToID:   make(map[string]int),
	}
}

func (idx *signedCertificateIndex) addPEM(id int, data []byte) {
	block, _ := pem.Decode(data)
	if block == nil {
		return
	}

	if block.Type != "CERTIFICATE" {
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}

	if len(cert.AuthorityKeyId) > 0 {
		idx.idToAuthorityKey[id] = string(cert.AuthorityKeyId)
	}
	if len(cert.SubjectKeyId) > 0 {
		idx.subjectKeyToID[string(cert.SubjectKeyId)] = id
	}
}

func (idx *signedCertificateIndex) depthMap() map[int]int {
	depth := make(map[int]int)
	for _, id := range idx.subjectKeyToID {
		// use a set to avoid cycles
		seen := set.From([]int{id})
		for {
			depth[id]++

			authorityKey, ok := idx.idToAuthorityKey[id]
			if !ok {
				break
			}

			id, ok = idx.subjectKeyToID[authorityKey]
			if !ok {
				break
			}

			if seen.Contains(id) {
				break
			}
			seen.Insert(id)
		}
	}
	return depth
}

// NormalizePEM takes PEM-encoded data and normalizes it.
//
// If the PEM data contains multiple certificates, signing certificates
// will be moved after the things they sign.
func NormalizePEM(data []byte) []byte {
	// make sure the file has a trailing newline
	if len(data) > 0 && !bytes.HasSuffix(data, []byte{'\n'}) {
		data = append(data, '\n')
	}

	type Segment struct {
		ID   int
		Data []byte
	}
	var segments []Segment
	for block := range iteratePEM(data) {
		segments = append(segments, Segment{ID: len(segments), Data: block})
	}

	// build a lookup table for subject keys and authority keys
	// a certificate with an authority key set to the subject key
	// of another certificate should appear before that certificate
	idx := newSignedCertificateIndex()
	for _, segment := range segments {
		idx.addPEM(segment.ID, segment.Data)
	}

	// calculate the depth of each certificate, deeper certificates will appear last
	depth := idx.depthMap()

	// sort the segments
	slices.SortStableFunc(segments, func(x, y Segment) int {
		return cmp.Compare(depth[x.ID], depth[y.ID])
	})

	// join the segments back together
	var buf bytes.Buffer
	for _, segment := range segments {
		buf.Write(segment.Data)
	}
	return buf.Bytes()
}

var (
	pemBegin = []byte("-----BEGIN ")
	pemEnd   = []byte("-----END ")
)

// splitPEM attempts to split a slice of bytes into a single pem block
// followed by the rest of the data. The pem block may contain extra
// text before the BEGIN but won't contain more than one pem block.
func splitPEM(data []byte) (before, after []byte) {
	idx1 := bytes.Index(data, pemBegin)
	if idx1 < 0 {
		return data, nil
	}

	idx2 := bytes.IndexByte(data[idx1+len(pemBegin):], '\n')
	if idx2 < 0 {
		return data, nil
	}
	idx2 += idx1 + len(pemBegin)

	idx3 := bytes.Index(data[idx2+1:], pemEnd)
	if idx3 < 0 {
		return data, nil
	}
	idx3 += idx2 + 1

	idx4 := bytes.IndexByte(data[idx3+len(pemEnd):], '\n')
	if idx4 < 0 {
		return data, nil
	}
	idx4 += idx3 + len(pemEnd)

	return data[:idx4+1], data[idx4+1:]
}

// iteratePEM iterates over all the raw PEM blocks
func iteratePEM(data []byte) iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		rest := data
		for len(rest) > 0 {
			before, after := splitPEM(rest)
			if !yield(before) {
				return
			}
			rest = after
		}
	}
}
