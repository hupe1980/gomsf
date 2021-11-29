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

	if err = client.Login("test", "pass"); err != nil {
		panic(err)
	}
	defer client.Logout()

	if err = client.HealthCheck(); err != nil {
		panic(err)
	}

	version, err := client.CoreVersion()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Version: %s\nRuby: %s\nAPI: %s\n\n\n", version.Version, version.Ruby, version.API)

	enocodeResult, err := client.ModuleEncode("AAAA", "x86/shikata_ga_nai", &gomsf.EncodingOptions{
		Format: "c",
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("'AAAA' encoded with shikata_ga_nai:")
	fmt.Printf("%s\n", enocodeResult.Encoded)

	infoResult, err := client.ModuleInfo(gomsf.Exploit, "windows/smb/ms08_067_netapi")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Name: %s\n", infoResult.Name)
	fmt.Printf("Rank: %s\n", infoResult.Rank)

	executeResult, err := client.ModuleExecute(gomsf.Exploit, "multi/handler", map[string]interface{}{
		"LHOST":   "0.0.0.0",
		"LPORT":   4444,
		"PAYLOAD": "generic/shell_reverse_tcp",
	})
	if err != nil {
		panic(err)
	}

	fmt.Printf("JobID: %d\n", executeResult.JobID)
	fmt.Printf("UUID: %s\n", executeResult.UUID)
}
