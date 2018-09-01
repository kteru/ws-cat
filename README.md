ws-cat
======

cat for WebSocket

Installation
------------

```
$ go get -u github.com/kteru/ws-cat
```

Usage
-----

```
$ ws-cat wss://echo.websocket.org
```

```
$ ws-cat -h
Usage:
  ws-cat [OPTIONS] URL

Application Options:
  -H, --header=   Add header from <key:value> (Repeat to set multiple)
  -o, --origin=   Set origin
  -u, --user=     Add header for basic authentication from <username:password>
  -k, --insecure  Disable verifing server certificates
      --cacert=   Set CA
      --cert=     Set a client certificate
      --key=      Set a client certificate's key
      --text      Use text frame when sending instead of binary
      --no-comp   Disable compression
      --no-ctx    Disable context takeover

Help Options:
  -h, --help      Show this help message
```
