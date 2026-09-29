package main

import (
	"context"
	"io"
	"slices"
	"testing"
)

type outputRunner struct{ output string }

func (r outputRunner) Run(_ context.Context, _ string, _ []string, _ io.Reader, stdout io.Writer) error {
	_, err := io.WriteString(stdout, r.output)
	return err
}

func TestProcessSourceStreamsLines(t *testing.T) {
	source := processSource{runner: outputRunner{output: "first\nsecond\n"}, name: "fake"}
	var lines []string
	err := source.Follow(t.Context(), func(line string) error { lines = append(lines, line); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(lines, []string{"first", "second"}) {
		t.Fatalf("lines = %v", lines)
	}
}
