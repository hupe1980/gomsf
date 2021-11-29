# gomsf
![Build Status](https://github.com/hupe1980/gomsf/workflows/build/badge.svg) 
[![Go Reference](https://pkg.go.dev/badge/github.com/hupe1980/gomsf.svg)](https://pkg.go.dev/github.com/hupe1980/gomsf)
> Golang based RPC client to communicate with Metasploit

https://docs.rapid7.com/metasploit/rpc-api

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
## Encode data with an encoder
```golang
enocdeResult, err := client.ModuleEncode("AAAA", "x86/shikata_ga_nai", gomsf.EncodingOptions{Format: "c"})
if err != nil {
    panic(err)
}
fmt.Printf("%s\n", enocdeResult.Encoded)
```
This will encode 'AAAA' with shikata_ga_nai, and prints the following:
```c
unsigned char buf[] =
"\xbd\x66\xf8\x8b\x6c\xda\xc2\xd9\x74\x24\xf4\x5f\x29\xc9\xb1"
"\x02\x31\x6f\x12\x03\x6f\x12\x83\x89\x04\x69\x99\x14\xb4\x2f"
"\x23";
```
## License
[MIT](LICENCE)
