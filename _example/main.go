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

	// encodeResult, err := client.Module.Encode("AAAA", "x86/shikata_ga_nai", &rpc.EncodingOptions{
	// 	Format: "c",
	// })
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println("'AAAA' encoded with shikata_ga_nai:")
	// fmt.Printf("%s\n", encodeResult.Encoded)

	// infoResult, err := client.Module.Info(rpc.Exploit, "windows/smb/ms08_067_netapi")
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Printf("Name: %s\n", infoResult.Name)
	// fmt.Printf("Rank: %s\n", infoResult.Rank)

	// moduleOptions := rpc.NewModuleOptions()
	// moduleOptions.SetStringOption("LHOST", "0.0.0.0")
	// moduleOptions.SetIntOption("LPORT", 4444)
	// moduleOptions.SetStringOption("PAYLOAD", "generic/shell_reverse_tcp")

	// executeResult, err := client.Module.Execute(rpc.Exploit, "multi/handler", moduleOptions)
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Printf("JobID: %d\n", executeResult.JobID)
	// fmt.Printf("UUID: %s\n", executeResult.UUID)
}
