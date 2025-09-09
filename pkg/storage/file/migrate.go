package file

import (
	"errors"
	"fmt"

	"github.com/cockroachdb/pebble/v2"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func migrate(db *pebble.DB) error {
	migrations := []func() error{
		func() error {
			return errors.Join(
				metadataKeySpace.setServerVersion(db, cryptutil.NewRandomUInt64()),
			)
		},
		func() error {
			return errors.Join(
				metadataKeySpace.setLeaderServerVersion(db, 0),
				metadataKeySpace.setLeaderLatestRecordVersion(db, 0),
			)
		},
	}

	current, err := metadataKeySpace.getMigration(db)
	if errors.Is(err, pebble.ErrNotFound) {
		current = 0
	} else if err != nil {
		return fmt.Errorf("pebble: error getting migration version: %w", err)
	}

	for i := current; i < uint64(len(migrations)); i++ {
		err = migrations[i]()
		if err != nil {
			return fmt.Errorf("pebble: error migrating to version %d: %w", i+1, err)
		}

		err = metadataKeySpace.setMigration(db, i+1)
		if err != nil {
			return fmt.Errorf("pebble: error setting migration version %d: %w", i+1, err)
		}
	}

	return nil
}
