package drivers

import (
	"context"
	"sync"

	gblob "gocloud.dev/blob"
)

var (
	driverMu             sync.Mutex
	DefaultListDrivers   = []ListDriver{}
	DefaultWriterDrivers = []WriterDriver{}
	DefaultReaderDrivers = []ReaderDriver{}
)

func RegisterListDrivers(drs ...ListDriver) {
	driverMu.Lock()
	defer driverMu.Unlock()
	DefaultListDrivers = append(DefaultListDrivers, drs...)
}

func RegisterWriterDriver(drs ...WriterDriver) {
	driverMu.Lock()
	defer driverMu.Unlock()
	DefaultWriterDrivers = append(DefaultWriterDrivers, drs...)
}

func RegisterReaderDriver(drs ...ReaderDriver) {
	driverMu.Lock()
	defer driverMu.Unlock()
	DefaultReaderDrivers = append(DefaultReaderDrivers, drs...)
}

// ListDrivers allows for types to chain configuring gblob ListOptions
type ListDriver interface {
	ApplyList(context.Context, *gblob.ListOptions)
}

// WriterDriver allows for types to chain configuring gblob.WriterOptions
type WriterDriver interface {
	ApplyWriter(context.Context, *gblob.WriterOptions)
}

// ReaderDriver allows for types to chain configuring gblob.ReaderOptions
type ReaderDriver interface {
	ApplyReader(context.Context, *gblob.ReaderOptions)
}

type beforeFunc = func(asFunc func(any) bool) error

func chainBeforeFunc(cur, next beforeFunc) beforeFunc {
	if cur == nil {
		return next
	}
	return func(asFunc func(any) bool) error {
		if err := next(asFunc); err != nil {
			return err
		}
		return cur(asFunc)
	}
}

func HandleMutateBeforeList(options *gblob.ListOptions, f beforeFunc) {
	options.BeforeList = chainBeforeFunc(options.BeforeList, f)
}

func HandleMutateBeforeWrite(options *gblob.WriterOptions, f beforeFunc) {
	options.BeforeWrite = chainBeforeFunc(options.BeforeWrite, f)
}

func HandleMutateBeforeRead(options *gblob.ReaderOptions, f beforeFunc) {
	options.BeforeRead = chainBeforeFunc(options.BeforeRead, f)
}
