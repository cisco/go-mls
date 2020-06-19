Message Layer Security
======================

[![Coverage Status](https://coveralls.io/repos/github/cisco/go-mls/badge.svg)](https://coveralls.io/github/cisco/go-mls)

This is a protocol to do group key establishment in an asynchronous,
message-oriented setting.  Its core ideas borrow a lot from
[Asynchronous Ratchet Trees](https://eprint.iacr.org/2017/666.pdf).

Right now, this is just a Go library that implements the core
protocol.  It is missing key things like message sequencing,
deconfliction, and retransmission.  The interface should not be
considered stable.

The most you can really do with it is run the tests:

```
> go test -v
```

The tests in `state_test.go` will illustrate the basic flows that
are supported.
