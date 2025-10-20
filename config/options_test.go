package config

import (
	"os"
	"testing"

	"github.com/moloch--/sgn/utils"
)

func TestConfigureOptionsSuccess(t *testing.T) {
	originalArgs := os.Args
	defer func() { os.Args = originalArgs }()
	utils.Verbose = false
	defer func() { utils.Verbose = false }()

	os.Args = []string{
		"sgn",
		"--input", "input.bin",
		"--out", "encoded.bin",
		"--arch", "32",
		"--enc", "2",
		"--max", "40",
		"--plain",
		"--safe",
		"--verbose",
	}

	opts, err := ConfigureOptions()
	if err != nil {
		t.Fatalf("unexpected error configuring options: %v", err)
	}
	if opts.Input != "input.bin" {
		t.Fatalf("expected input path 'input.bin', got %q", opts.Input)
	}
	if opts.Output != "encoded.bin" {
		t.Fatalf("expected output path 'encoded.bin', got %q", opts.Output)
	}
	if opts.Arch != 32 {
		t.Fatalf("expected architecture 32, got %d", opts.Arch)
	}
	if opts.EncCount != 2 {
		t.Fatalf("expected encoding count 2, got %d", opts.EncCount)
	}
	if opts.ObsLevel != 40 {
		t.Fatalf("expected obfuscation level 40, got %d", opts.ObsLevel)
	}
	if !opts.PlainDecoder {
		t.Fatal("expected plain decoder flag to be set")
	}
	if !opts.Safe {
		t.Fatal("expected safe flag to be set")
	}
	if !utils.Verbose {
		t.Fatal("expected verbose flag to enable verbose output")
	}
}

func TestConfigureOptionsMissingInput(t *testing.T) {
	originalArgs := os.Args
	defer func() { os.Args = originalArgs }()
	utils.Verbose = false
	defer func() { utils.Verbose = false }()

	os.Args = []string{"sgn", "--arch", "64"}
	if _, err := ConfigureOptions(); err == nil {
		t.Fatal("expected error when input parameter is missing")
	}
}
