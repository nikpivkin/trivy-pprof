package main

import (
	"log"
	"os"
	"runtime/pprof"

	"github.com/aquasecurity/trivy/pkg/commands"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cpuf, err := os.Create("cpu.prof")
	if err != nil {
		return err
	}
	defer cpuf.Close()

	if err := pprof.StartCPUProfile(cpuf); err != nil {
		return err
	}
	defer pprof.StopCPUProfile()

	app := commands.NewApp()
	if err := app.Execute(); err != nil {
		return err
	}

	heapf, err := os.Create("heap.prof")
	if err != nil {
		return err
	}
	defer heapf.Close()

	if err := pprof.WriteHeapProfile(heapf); err != nil {
		return err
	}
	return nil
}
