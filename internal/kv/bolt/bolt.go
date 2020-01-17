package bolt

import (
	"context"

	"github.com/pomerium/pomerium/internal/kv"

	bolt "go.etcd.io/bbolt"
)

var _ kv.Store = &Store{}

// Name represents bbolt's shorthand named.
const Name = "bolt"

// Store implements a the Store interface for bolt.
// https://godoc.org/github.com/etcd-io/bbolt
type Store struct {
	db     *bolt.DB
	bucket string
}

// Options represents options for configuring the boltdb cache store.
type Options struct {
	// Buckets are collections of key/value pairs within the database.
	// All keys in a bucket must be unique.
	Bucket string
	// Path is where the database file will be stored.
	Path string
}

// DefaultOptions contain's bolts default options.
var DefaultOptions = &Options{
	Bucket: "default",
	Path:   Name + ".db",
}

// New creates a new bolt cache store.
// It is up to the operator to make sure that the store's path
// is writeable.
func New(o *Options) (*Store, error) {
	if o.Path == "" {
		o.Path = DefaultOptions.Path
	}
	if o.Bucket == "" {
		o.Bucket = DefaultOptions.Bucket
	}

	db, err := bolt.Open(o.Path, 0600, nil)
	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(o.Bucket))
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &Store{db: db, bucket: o.Bucket}, nil
}

// Set sets the value for a key in the bucket.
// If the key exist then its previous value will be overwritten.
// Supplied value must remain valid for the life of the transaction.
// Returns an error if the bucket was created from a read-only transaction,
// if the key is blank, if the key is too large, or if the value is too large.
func (s Store) Set(ctx context.Context, k string, v []byte) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(s.bucket))
		return b.Put([]byte(k), v)
	})
	if err != nil {
		return err
	}
	return nil
}

// Get retrieves the value for a key in the bucket.
// Returns a nil value if the key does not exist or if the key is a nested bucket.
// The returned value is only valid for the life of the transaction.
func (s *Store) Get(ctx context.Context, k string) (bool, []byte, error) {
	var value []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(s.bucket))
		txData := b.Get([]byte(k)) // only valid in transaction
		value = append(txData[:0:0], txData...)
		return nil
	})
	if err != nil {
		return false, nil, err
	}
	if value == nil {
		return false, nil, nil
	}
	return true, value, nil
}

// Close releases all database resources.
// It will block waiting for any open transactions to finish
// before closing the database and returning.
func (s Store) Close(ctx context.Context) error {
	return s.db.Close()
}
