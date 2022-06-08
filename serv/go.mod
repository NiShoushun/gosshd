module github.com/nishoushun/gosshd/serv

go 1.18

require (
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be
	github.com/nishoushun/gosshd v0.0.0-20220529102405-24d453e4b487
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e
)

require golang.org/x/sys v0.0.0-20220503163025-988cb79eb6c6 // indirect

replace (
	github.com/nishoushun/gosshd => ../
)
