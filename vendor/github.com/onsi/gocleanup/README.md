GoCleanup
=========

It's kinda like atexit()

GoCleanup is a big bag of singleton methods to enable `atexit`-like behavior in Golang.  If you don't like singletons... move along ;)

It's simple.  You register functions to run on exit with

```go
gocleanup.Register(func() {
    //do stuff
})
```

If the running program receives a SIGINT, or SIGTERM cleanup will intercept the signal, run all the registered clean up functions and then exit with status 1.

If you want to exit from within your code, you'll need to call

```go
gocleanup.Exit(statuscode)
```

to ensure the cleanup callbacks are run.

Finally, if you want to manually invoke the cleanup callbacks (without exiting):

```go
gocleanup.Cleanup()
```

this will also unregister any registered cleanup functions.