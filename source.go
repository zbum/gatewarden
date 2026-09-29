package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
)

type lineSource interface {
	Follow(context.Context, func(string) error) error
}
type commandRunner interface {
	Run(context.Context, string, []string, io.Reader, io.Writer) error
}
type processSource struct {
	runner commandRunner
	name   string
	args   []string
}

func (s processSource) Follow(ctx context.Context, consume func(string) error) error {
	reader, writer := io.Pipe()
	errCh := make(chan error, 1)
	go func() { errCh <- s.runner.Run(ctx, s.name, s.args, nil, writer); _ = writer.Close() }()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if err := consume(scanner.Text()); err != nil {
			_ = reader.CloseWithError(err)
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read log stream: %w", err)
	}
	if err := <-errCh; err != nil && ctx.Err() == nil {
		return fmt.Errorf("follow logs: %w", err)
	}
	return nil
}
