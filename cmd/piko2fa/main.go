package main

import (
	"fmt"
	"os"

	"piko2fa/internal/cli"
)

func main() {
	app, err := cli.New()
	if err == nil {
		err = app.Execute(os.Args[1:])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "piko2fa:", err)
		os.Exit(1)
	}
}
