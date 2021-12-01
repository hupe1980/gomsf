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
encoded, err := client.Module.Encode("AAAA", "x86/shikata_ga_nai", &gomsf.EncodeOptions{
    Format: "c",
})
if err != nil {
    panic(err)
}
fmt.Printf("%s\n", encoded)
```
This will encode 'AAAA' with shikata_ga_nai, and prints the following c code:
```bash
unsigned char buf[] =
"\xbb\xc6\xee\x4d\x66\xd9\xee\xd9\x74\x24\xf4\x58\x33\xc9\xb1"
"\x02\x31\x58\x12\x83\xe8\xfc\x03\x9e\xe0\xaf\x93\x5f\xbc\x6e"
"\x1d";
```
## Get infos about a module
```golang
info, err := client.Module.Info(gomsf.ExploitType, "windows/smb/ms08_067_netapi")
if err != nil {
    panic(err)
}

fmt.Printf("Name: %s\n", info.Name)
fmt.Printf("Rank: %s\n", info.Rank)
```
This gives us the metadata of ms08_067_netapi
```bash
Name: MS08-067 Microsoft Server Service Relative Path Stack Corruption
Rank: great
```

## License
[MIT](LICENCE)
