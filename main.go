package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/arl/statsviz"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	mux := http.NewServeMux()
	statsviz.Register(mux)

	go func() {
		log.Println(http.ListenAndServe("localhost:8080", mux))
	}()

	cpuf, _ := os.Create("cpu.prof")
	defer cpuf.Close()

	if err := pprof.StartCPUProfile(cpuf); err != nil {
		return err
	}
	defer pprof.StopCPUProfile()

	defer func() {
		heapf, _ := os.Create("heap.prof")
		pprof.WriteHeapProfile(heapf)

	}()

	sig := make(chan os.Signal, 1)

	go func() {
		<-sig
		pprof.StopCPUProfile()
		heapf, _ := os.Create("heap.prof")
		pprof.WriteHeapProfile(heapf)
		os.Exit(0)
	}()

	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	app := commands.NewApp()
	if err := app.Execute(); err != nil {
		return err
	}
	return nil
}
