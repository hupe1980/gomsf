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
## Encode data with an encoder
```golang
enocodeResult, err := client.ModuleEncode("AAAA", "x86/shikata_ga_nai", &gomsf.EncodingOptions{
    Format: "c",
})
if err != nil {
    panic(err)
}
fmt.Printf("%s\n", enocodeResult.Encoded)
```
This will encode 'AAAA' with shikata_ga_nai, and prints the following c code:
```c
unsigned char buf[] =
"\xbd\x66\xf8\x8b\x6c\xda\xc2\xd9\x74\x24\xf4\x5f\x29\xc9\xb1"
"\x02\x31\x6f\x12\x03\x6f\x12\x83\x89\x04\x69\x99\x14\xb4\x2f"
"\x23";
```

## Get infos about a module
```golang
infoResult, err := client.ModuleInfo(gomsf.Exploit, "windows/smb/ms08_067_netapi")
if err != nil {
    panic(err)
}
fmt.Printf("Name: %s\n", infoResult.Name)
fmt.Printf("Rank: %s\n", infoResult.Rank)
```
This gives us the metadata of ms08_067_netapi
```bash
Name: MS08-067 Microsoft Server Service Relative Path Stack Corruption
Rank: great
```
## License
[MIT](LICENCE)
