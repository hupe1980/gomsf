package main

import (
	"fmt"

	"github.com/hupe1980/gomsf"
)

func main() {
	client, err := gomsf.New("0.0.0.0:55553")
	if err != nil {
		panic(err)
	}

	if err = client.Login("user", "pass"); err != nil {
		panic(err)
	}
	defer client.Logout()

	if err = client.HealthCheck(); err != nil {
		panic(err)
	}

	version, err := client.Core.Version()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Version: %s\nRuby: %s\nAPI: %s\n\n", version.Version, version.Ruby, version.API)

	encoded, err := client.Module.Encode("AAAA", "x86/shikata_ga_nai", &gomsf.EncodeOptions{
		Format: "c",
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("'AAAA' encoded with shikata_ga_nai:")
	fmt.Printf("%s\n", encoded)

	exploit, err := client.Module.UseExploit("unix/ftp/vsftpd_234_backdoor")
	if err != nil {
		panic(err)
	}

	fmt.Println(exploit.Options())

	fmt.Println(exploit.Required())

	info, err := client.Module.Info(gomsf.ExploitType, "windows/smb/ms08_067_netapi")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Name: %s\n", info.Name)
	fmt.Printf("Rank: %s\n", info.Rank)
}
