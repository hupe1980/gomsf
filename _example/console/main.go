package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

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

	console, err := client.Consoles.Console()
	if err != nil {
		panic(err)
	}

	reader := bufio.NewReader(os.Stdin)

	for {
		r, err := console.Read()
		if err != nil {
			panic(err)
		}

		if r.Busy {
			continue
		}

		if r.Data == "" {
			continue
		}

		fmt.Println(r.Data)
		fmt.Print(r.Prompt)

		input, err := reader.ReadString('\n')
		if err != nil {
			panic(err)
		}

		input = strings.TrimSuffix(input, "\n")

		if input == "exit" {
			err = console.Destroy()
			if err != nil {
				panic(err)
			}

			os.Exit(0)
		}

		err = console.Write(input)
		if err != nil {
			panic(err)
		}
	}
}
