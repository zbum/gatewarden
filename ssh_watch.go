package main

import (
	"context"
	"log"
)

type sessionWatcher interface {
	Run(context.Context, *manager, *log.Logger) error
	Close() error
}

// idleWatcher is the dry-run watcher. It does not attach tracepoints.
type idleWatcher struct{}

func (idleWatcher) Run(ctx context.Context, _ *manager, _ *log.Logger) error {
	<-ctx.Done()
	return nil
}

func (idleWatcher) Close() error { return nil }
