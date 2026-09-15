// Command imhotep is the QYVORA cloud security assessment framework.
package main

import (
	"os"

	"github.com/QYVORA/qyvora-imhotep/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
