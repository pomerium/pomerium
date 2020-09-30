resources-go
============

An assets-loading package for Go.

Applications can use this package to load assets from zip-files (incuding a zip file bundled in the executable),
the filesystem, or other sources through a single interface. Also allows for the building of a search path to access
files sequentially through a set of application defined locations.

This is the v2 version of the API. Access to the current version as well as more recent versions can be found at: <https://github.com/cookieo9/resources-go>

[![Build Status](https://travis-ci.org/cookieo9/resources-go.svg?branch=v2.1)](https://travis-ci.org/cookieo9/resources-go)
[![GoDoc](https://godoc.org/gopkg.in/cookieo9/resources-go.v2?status.png)](https://godoc.org/gopkg.in/cookieo9/resources-go.v2)
[![Coverage](http://gocover.io/_badge/gopkg.in/cookieo9/resources-go.v2)](http://gocover.io/gopkg.in/cookieo9/resources-go.v2)

Documentation and Other Versions
--------------------------------

To see the code and documentation for every released version of this package, see: http://gopkg.in/cookieo9/resources-go.v2

Package Path and Name
---------------------

This package is go-gettable with the path:

	gopkg.in/cookieo9/resources-go.v2
	
The name of the package is `resources`. 

Code that used the old import path `github.com/cookieo9/resources-go/v2/resources` (before the switch to using branches) can simply use the new path while leaving all other code unchanged.

Embedding Zip-Files
-------------------

To embed a zip file into your executable do the following:
 - Create executable (eg: go build -o myApp)
 - Create zip file  (eg: zip -r assets.zip assets)
 - Append zip file to executable (eg: cat assets.zip >> myApp)
 - Adjust the offsets in the zip header (optional) (zip -A myApp)

License
-------
http://cookieo9.mit-license.org/2012
