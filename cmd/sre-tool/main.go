// Command sre-tool isolates workloads from each other's network traffic and
// hardens workloads that lack resource or securityContext settings.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is set at build time with -ldflags "-X main.version=<git sha>".
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	fmt.Fprintln(os.Stderr, "sre-tool: the server is not implemented yet")
	os.Exit(1)
}
