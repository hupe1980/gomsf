# gomsf
![Build Status](https://github.com/hupe1980/gomsf/workflows/build/badge.svg) 
[![Go Reference](https://pkg.go.dev/badge/github.com/hupe1980/gomsf.svg)](https://pkg.go.dev/github.com/hupe1980/gomsf)
> Golang based RPC client to communicate with Metasploit

https://docs.rapid7.com/metasploit/rpc-api

:warning: This is experimental and subject to breaking changes.

## Starting the RPC Server for Metasploit
```bash
msfrpcd -U user -P pass
```

## Connecting to the RPC Server
```golang
client, err := gomsf.New("0.0.0.0:55553")
if err != nil {
    panic(err)
}
if err := client.Login("user", "pass"); err != nil {
    panic(err)
}
defer client.Logout()
```

## License
[MIT](LICENCE)
