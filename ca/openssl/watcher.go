package openssl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/log"
)

type WatchOpt func(*watcher)

func (txt *IndexTXT) WatchFiles(ctx context.Context, opts ...WatchOpt) error {
	wtr, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	w := watcher{txt: txt, watcher: wtr}
	for _, cfg := range txt.cfgs {
		if err = w.watcher.Add(cfg.Index); err != nil {
			return err
		}
	}
	for _, o := range opts {
		o(&w)
	}
	go w.watch(ctx)
	return nil
}

func WithEventChannel(ch chan string) WatchOpt {
	return func(w *watcher) {
		w.channels = append(w.channels, ch)
	}
}

type watcher struct {
	txt      *IndexTXT
	watcher  *fsnotify.Watcher
	channels []chan string
}

func (w *watcher) watch(ctx context.Context) {
	logger := log.ContextLogger(ctx).
		WithField("component", "openssl-index-file-watcher")
	defer func() {
		if err := w.watcher.Close(); err != nil {
			logger.WithError(err).Error("failed to close file watcher")
		}
		for _, ch := range w.channels {
			close(ch)
		}
	}()
	logger.WithField("files", w.watcher.WatchList()).Info("watching for file changes")
	for {
		select {
		case <-ctx.Done():
			logger.Info("closing file watcher")
			return
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			l := logger.WithFields(logrus.Fields{
				"op":   event.Op.String(),
				"name": event.Name,
				"time": time.Now(),
			})
			l.Debug("received file watcher event")
			err := w.handleEvent(l, &event)
			if err != nil {
				l.WithError(err).Error("failed to handle file event")
			}
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			logger.WithError(err).Error("received error from file watcher")
		}
	}
}

func (w *watcher) handleEvent(l logrus.FieldLogger, event *fsnotify.Event) error {
	ix, cfg := w.findIndexConfig(event.Name)
	if cfg == nil {
		return errors.New("got event for untracked index config")
	}
	// If the operation was REMOVE but the file still exists then we will want
	// to add it back to the pool of files being watched.
	if isOp(event, fsnotify.Remove) && exists(event.Name) {
		err := w.watcher.Add(event.Name)
		if err != nil {
			l.WithError(err).Error("failed to add file back to event listener pool")
			return err
		}
	}
	f, err := os.Open(event.Name)
	if err != nil {
		return err
	}
	defer f.Close()
	entries, err := parseIndex(f)
	if err != nil {
		return err
	}
	w.txt.mu.Lock()
	for _, entry := range entries {
		k := key(entry.serial, ix)
		old, ok := w.txt.certs[k]
		// The in-memory status should hold precedence over the new file changes
		if ok && old.Status != ca.Valid && entry.Status == ca.Valid {
			entry.Status = old.Status
		}
		w.txt.certs[k] = *entry
	}
	w.txt.mu.Unlock()
	// Notify all that a change has been registered
	for _, ch := range w.channels {
		go func(ch chan string) { ch <- event.Name }(ch)
	}
	return nil
}

func isOp(event *fsnotify.Event, op fsnotify.Op) bool {
	return event.Op&op == op
}

func (w *watcher) findIndexConfig(filename string) (uint8, *IndexConfig) {
	fn := filepath.Clean(filename)
	for i, cfg := range w.txt.cfgs {
		if filepath.Clean(cfg.Index) == fn {
			return uint8(i), &cfg
		}
	}
	return 0, nil
}

func exists(s string) bool {
	_, err := os.Stat(s)
	return !os.IsNotExist(err)
}
