# encrypted-socks5 server

This is a small TCP/UDP SOCKS5 server for the `encrypted-socks5` outbound adapter.

It listens for encrypted SOCKS5 traffic, applies the same 0-255 substitution
wheel as the client, handles SOCKS5 CONNECT and UDP ASSOCIATE, dials the final
target directly, and relays traffic.

## Run

```powershell
go run .\cmd\encrypted-socks5-server -listen 127.0.0.1:1081 -password demo-secret
```

Start mihomo with the test config:

```powershell
go run . -f .\test-encrypted-socks5.yaml
```

Test through mihomo:

```powershell
curl.exe -x http://127.0.0.1:7890 https://www.gstatic.com/generate_204 -v
```

The `-password` option is kept only for compatibility with older test commands.
The current toy protocol uses a fixed 256-byte substitution wheel.

UDP ASSOCIATE is implemented as a small stateless test path: each client UDP
datagram is decoded, sent to the target, and one response datagram is relayed
back to the client.
