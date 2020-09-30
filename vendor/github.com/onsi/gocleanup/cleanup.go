/*
GoCleanup: kinda like atexit()...

GoCleanup packages allows you to register cleanup functions.
These are called whenever the current process receives a SIGINT or SIGTERM

You can also invoke the cleanup functions by calling Cleanup().

Unfortunately, it is not possible for cleanup to intercept calls to os.Exit() and perform cleanup befor the
process exits.  Instead of os.Exit, you can use cleanup.Exit()

Cleanup is especially useful when forking off external processes.  You can register
callbacks with this package to tear down these external processes.
*/

package gocleanup

import (
	"os"
	"os/signal"
	"syscall"
)

var cleanupFuncs []func()
var capturingSignals bool

//Register a cleanup function.  This will be called when:
//- a call is made to Cleanup()
//- a call is made to Exit()
//- the current process receives SIGINT or SIGTERM
func Register(f func()) {
	cleanupFuncs = append(cleanupFuncs, f)
	if !capturingSignals {
		capturingSignals = true
		go func() {
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGINT, syscall.SIGKILL, syscall.SIGTERM)

			<-c
			Exit(1)
		}()
	}
}

//Cleanup invokes all registered cleanup functions
//all registered cleanup functions are subsequently removed
func Cleanup() {
	for _, f := range cleanupFuncs {
		f()
	}
	cleanupFuncs = []func(){}
}

//Exit invokes all registered cleanup functions, then exits
func Exit(status int) {
	Cleanup()
	os.Exit(status)
}
