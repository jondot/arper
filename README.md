# Arper

A network utility and library for discovering network device via ARP scans, including vendor names.

## Quick Start

Get `arper`:

```
$ go get github.com/jondot/arper/...
```

Then run it (make sure to use `sudo`) and wait 10 seconds:

```
$ sudo arper
192.168.50.1	00:16:0a:xx:xx:xx	SWEEX Europe BV
192.168.99.6	08:00:27:xx:xx:xx	Cadmus Computer Systems
192.168.50.42	00:26:73:xx:xx:xx	RICOH COMPANY,LTD.
192.168.99.100	08:00:27:xx:xx:xx	Cadmus Computer Systems
```

Options are quite simple:

```
$ arper --help
Usage of arper:
  -timeout uint
    	Timeout in seconds (default 10)
  -verbose
    	Verbose logging
```

## As a Library

A better use for `arper` is as a library


```go
import(
	"github.com/jondot/arper"
)
arp, err := arper.New()
if err != nil {
  fmt.Printf("Error: %v", err)
  os.Exit(1)
}

devices, err := arp.Scan(time.Second * time.Duration(*timeout))
```

Since ARP scans are fuzzy, you can scan again by supplying a different duration, have your own repeat scan intervals
and so on with the same `arper` instance.

# Contributing

Fork, implement, add tests, pull request, get my everlasting thanks and a respectable place here :).


### Thanks:

To all [Contributors](https://github.com/jondot/arper/graphs/contributors) - you make this happen, thanks!


# Copyright

Copyright (c) 2016 [Dotan Nahum](http://gplus.to/dotan) [@jondot](http://twitter.com/jondot). See [LICENSE](LICENSE.txt) for further details.
