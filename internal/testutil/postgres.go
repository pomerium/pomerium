package testutil

import (
	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
)

// WithTestPostgres creates a test a test postgres instance.
func WithTestPostgres(handler func(dsn string) error) error {
	postgres := embeddedpostgres.NewDatabase()
	err := postgres.Start()
	if err != nil {
		return err
	}
	defer func() { _ = postgres.Stop() }()

	return handler("host=localhost port=5432 user=postgres password=postgres dbname=postgres sslmode=disable")
}
