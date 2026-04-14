package middleware

import (
	"context"
	"sync"

	gblob "gocloud.dev/blob"
)

type ListOp struct {
	Ctx  context.Context
	Opts *gblob.ListOptions
}

type WriteOp struct {
	Ctx  context.Context
	Opts *gblob.WriterOptions
}

type ReadOp struct {
	Ctx  context.Context
	Opts *gblob.ReaderOptions
}

type (
	ListMiddleware   func(*ListOp) error
	WriterMiddleware func(*WriteOp) error
	ReadMiddleware   func(*ReadOp) error
)

var (
	defaultMu               sync.Mutex
	DefaultListMiddleware   []ListMiddleware
	DefaultWriterMiddleware []WriterMiddleware
	DefaultReaderMiddleware []ReadMiddleware
)

func RegisterListMiddleware(mws ...ListMiddleware) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	DefaultListMiddleware = append(DefaultListMiddleware, mws...)
}

func RegisterWriterMiddleware(mws ...WriterMiddleware) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	DefaultWriterMiddleware = append(DefaultWriterMiddleware, mws...)
}

func RegisterReaderMiddleware(mws ...ReadMiddleware) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	DefaultReaderMiddleware = append(DefaultReaderMiddleware, mws...)
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
