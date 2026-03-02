// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/cache"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/sync/singleflight"
)

// cachePath returns the filesystem path for a cached layer by hash.
// Matches go-containerregistry pkg/v1/cache layout for compatibility.
func cachePath(basePath string, h v1.Hash) string {
	var file string
	if runtime.GOOS == "windows" {
		file = fmt.Sprintf("%s-%s", h.Algorithm, h.Hex)
	} else {
		file = h.String()
	}
	return filepath.Join(basePath, file)
}

// safeCache wraps a cache.Cache so that concurrent access to the same layer
// (same digest or diffID) is serialized. This prevents races when multiple
// goroutines validate images that share layers (e.g. same base image).
// See https://github.com/conforma/cli/issues/1109.
type safeCache struct {
	inner     cache.Cache
	path      string
	putFlight singleflight.Group
}

// NewSafeCache returns a cache.Cache that delegates to inner but ensures
// only one goroutine populates a given digest at a time. basePath must be
// the same path used by the inner filesystem cache so that written files
// are found by Get.
func NewSafeCache(inner cache.Cache, basePath string) cache.Cache {
	if inner == nil {
		return nil
	}
	return &safeCache{inner: inner, path: basePath}
}

// Get implements cache.Cache. Successful results are wrapped in safeLayer so
// Compressed()/Uncompressed() use the same stream serialization as layers from Put.
func (s *safeCache) Get(h v1.Hash) (v1.Layer, error) {
	layer, err := s.inner.Get(h)
	if err != nil {
		return nil, err
	}
	return &safeLayer{inner: layer, path: s.path, flight: &s.putFlight}, nil
}

// Put implements cache.Cache. Only one goroutine runs inner.Put for a given
// digest; others wait and receive the same result. The returned layer is
// wrapped so that Compressed() and Uncompressed() are also singleflighted,
// ensuring only one writer fills each cache file.
func (s *safeCache) Put(l v1.Layer) (v1.Layer, error) {
	digest, err := l.Digest()
	if err != nil {
		return nil, err
	}
	v, err, _ := s.putFlight.Do(digest.String(), func() (any, error) {
		layer, err := s.inner.Get(digest)
		if err == nil {
			return &safeLayer{inner: layer, path: s.path, flight: &s.putFlight}, nil
		}
		if !errors.Is(err, cache.ErrNotFound) {
			return nil, err
		}
		layer, err = s.inner.Put(l)
		if err != nil {
			return nil, err
		}
		return &safeLayer{inner: layer, path: s.path, flight: &s.putFlight}, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(v1.Layer), nil
}

// Delete implements cache.Cache.
func (s *safeCache) Delete(h v1.Hash) error {
	return s.inner.Delete(h)
}

// safeLayer wraps a layer that may write to the cache on first read.
// The first caller of Compressed() or Uncompressed() gets a streaming reader;
// the inner layer writes to the cache as data is read. When that reader is
// closed (after draining any remainder), concurrent callers are unblocked and
// read from the cached file. This preserves streaming and avoids full
// materialization before returning.
type safeLayer struct {
	inner  v1.Layer
	path   string
	flight *singleflight.Group

	// compressed: first caller streams; others wait on ready then open path.
	compressedMu    sync.Mutex
	compressedReady chan struct{} // closed when first caller's stream is done
	compressedErr   error         // set if streaming failed so waiters can return it

	uncompressedMu    sync.Mutex
	uncompressedReady chan struct{}
	uncompressedErr   error
}

// streamingCloseReader wraps a ReadCloser and drains then closes it, then
// signals ready so waiters can open the cache file.
type streamingCloseReader struct {
	rc    io.ReadCloser
	ready chan struct{}
	once  sync.Once
}

func (s *streamingCloseReader) Read(p []byte) (n int, err error) {
	return s.rc.Read(p)
}

func (s *streamingCloseReader) Close() error {
	var err error
	s.once.Do(func() {
		// Drain remainder so inner cache file is complete before signaling.
		_, _ = io.Copy(io.Discard, s.rc)
		err = s.rc.Close()
		close(s.ready)
	})
	return err
}

func (l *safeLayer) Digest() (v1.Hash, error)            { return l.inner.Digest() }
func (l *safeLayer) DiffID() (v1.Hash, error)            { return l.inner.DiffID() }
func (l *safeLayer) Size() (int64, error)                { return l.inner.Size() }
func (l *safeLayer) MediaType() (types.MediaType, error) { return l.inner.MediaType() }

func (l *safeLayer) Compressed() (io.ReadCloser, error) {
	digest, err := l.inner.Digest()
	if err != nil {
		return nil, err
	}
	path := cachePath(l.path, digest)

	l.compressedMu.Lock()
	if _, err := os.Stat(path); err == nil {
		l.compressedMu.Unlock()
		return os.Open(path)
	}
	if l.compressedReady != nil {
		ready := l.compressedReady
		l.compressedMu.Unlock()
		<-ready
		l.compressedMu.Lock()
		if l.compressedErr != nil {
			err := l.compressedErr
			l.compressedMu.Unlock()
			return nil, err
		}
		l.compressedMu.Unlock()
		return os.Open(path)
	}
	l.compressedReady = make(chan struct{})
	l.compressedMu.Unlock()

	rc, err := l.inner.Compressed()
	if err != nil {
		l.compressedMu.Lock()
		l.compressedErr = err
		close(l.compressedReady)
		l.compressedMu.Unlock()
		return nil, err
	}
	return &streamingCloseReader{rc: rc, ready: l.compressedReady}, nil
}

func (l *safeLayer) Uncompressed() (io.ReadCloser, error) {
	diffID, err := l.inner.DiffID()
	if err != nil {
		return nil, err
	}
	path := cachePath(l.path, diffID)

	l.uncompressedMu.Lock()
	if _, err := os.Stat(path); err == nil {
		l.uncompressedMu.Unlock()
		return os.Open(path)
	}
	if l.uncompressedReady != nil {
		ready := l.uncompressedReady
		l.uncompressedMu.Unlock()
		<-ready
		l.uncompressedMu.Lock()
		if l.uncompressedErr != nil {
			err := l.uncompressedErr
			l.uncompressedMu.Unlock()
			return nil, err
		}
		l.uncompressedMu.Unlock()
		return os.Open(path)
	}
	l.uncompressedReady = make(chan struct{})
	l.uncompressedMu.Unlock()

	rc, err := l.inner.Uncompressed()
	if err != nil {
		l.uncompressedMu.Lock()
		l.uncompressedErr = err
		close(l.uncompressedReady)
		l.uncompressedMu.Unlock()
		return nil, err
	}
	return &streamingCloseReader{rc: rc, ready: l.uncompressedReady}, nil
}
