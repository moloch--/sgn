package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/moloch--/sgn/internal/wasmstrip"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "wasmstrip: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("wasmstrip", flag.ContinueOnError)
	output := flags.String("o", "", "normalized output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *output == "" || flags.NArg() != 1 {
		return errors.New("usage: wasmstrip -o OUTPUT INPUT")
	}

	input, err := os.ReadFile(flags.Arg(0))
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	normalized, err := wasmstrip.StripCustomSections(input)
	if err != nil {
		return fmt.Errorf("normalize input: %w", err)
	}
	if err := writeFileAtomically(*output, normalized); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func writeFileAtomically(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".wasmstrip-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
