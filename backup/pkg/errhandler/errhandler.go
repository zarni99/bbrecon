package errhandler

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
)

var PrintBannerFunc func()

func SetPrintBannerFunc(f func()) {
	PrintBannerFunc = f
}

func SetupFlagHandling() {
	r, w, _ := os.Pipe()
	originalStderr := os.Stderr
	os.Stderr = w

	originalUsage := flag.Usage
	flag.Usage = func() {
		os.Stderr = originalStderr

		for _, arg := range os.Args {
			if arg == "-h" || arg == "--help" {
				originalUsage()
				return
			}
		}

		if PrintBannerFunc != nil {
			PrintBannerFunc()
		}

		usageText := color.HiCyanString("Usage:") + " " +
			color.HiWhiteString("./bbrecon") + " " +
			color.HiYellowString("-t") + " " +
			color.HiGreenString("example.com") + " " +
			color.HiWhiteString("or") + " " +
			color.HiWhiteString("./bbrecon") + " " +
			color.HiYellowString("-C") + " " +
			color.HiGreenString("targets.txt")

		helpText := color.HiCyanString("Use") + " " +
			color.HiYellowString("-h") + " " +
			color.HiCyanString("for detailed help information")

		fmt.Println(usageText)
		fmt.Println(helpText)
		os.Exit(2)
	}

	go func() {
		_, _ = io.ReadAll(r)
		_ = r.Close()
	}()
}
