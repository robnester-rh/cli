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

//go:build unit

package oci

import (
	"errors"
	"io"
	"sync"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/cache"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSafeCache_NilInnerReturnsNil(t *testing.T) {
	assert.Nil(t, NewSafeCache(nil, "/tmp/cache"))
}

func TestNewSafeCache_DelegatesGetAndDelete(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	layer, err := random.Layer(256, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)
	digest, err := layer.Digest()
	require.NoError(t, err)

	_, err = wrapped.Get(digest)
	assert.Error(t, err)
	assert.ErrorIs(t, err, cache.ErrNotFound)

	err = wrapped.Delete(digest)
	assert.Error(t, err)
}

// errCache is a cache.Cache that returns a specific error from Get to test
// that safeCache propagates non-ErrNotFound errors instead of treating them as miss.
type errCache struct {
	getErr error
}

func (e *errCache) Get(h v1.Hash) (v1.Layer, error)  { return nil, e.getErr }
func (e *errCache) Put(l v1.Layer) (v1.Layer, error) { return l, nil }
func (e *errCache) Delete(h v1.Hash) error           { return nil }

func TestNewSafeCache_PutPropagatesNonErrNotFoundFromGet(t *testing.T) {
	wantErr := errors.New("permission denied")
	inner := &errCache{getErr: wantErr}
	wrapped := NewSafeCache(inner, t.TempDir())
	require.NotNil(t, wrapped)

	layer, err := random.Layer(256, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)

	_, err = wrapped.Put(layer)
	assert.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

func TestNewSafeCache_ConcurrentPutSameLayer(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	layer, err := random.Layer(256, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)

	// Concurrent Put of the same layer (same digest), then read; must not race.
	// Run with: go test -race -tags=unit ./internal/utils/oci/ -run TestNewSafeCache_ConcurrentPutSameLayer
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			cached, err := wrapped.Put(layer)
			if err != nil {
				t.Error(err)
				done <- struct{}{}
				return
			}
			rc, err := cached.Compressed()
			if err != nil {
				t.Error(err)
				done <- struct{}{}
				return
			}
			_, _ = rc.Read(make([]byte, 4096))
			_ = rc.Close()
			done <- struct{}{}
		}()
	}
	for i := 0; i < 4; i++ {
		<-done
	}
}

// TestNewSafeCache_ConcurrentPutDifferentLayers ensures Put of different layers (different digests)
// does not block and all succeed without race.
func TestNewSafeCache_ConcurrentPutDifferentLayers(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	const numLayers = 8
	errCh := make(chan error, numLayers)
	var wg sync.WaitGroup
	for i := 0; i < numLayers; i++ {
		wg.Add(1)
		go func(size int) {
			defer wg.Done()
			layer, err := random.Layer(int64(size+1)*128, "application/vnd.oci.image.layer.v1.tar+gzip")
			if err != nil {
				errCh <- err
				return
			}
			cached, err := wrapped.Put(layer)
			if err != nil {
				errCh <- err
				return
			}
			rc, err := cached.Compressed()
			if err != nil {
				errCh <- err
				return
			}
			_, _ = io.Copy(io.Discard, rc)
			_ = rc.Close()
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}

// TestNewSafeCache_PutThenGetReturnsSameDigest ensures that after Put, Get returns a layer
// with the same digest (cache stores and retrieves correctly).
func TestNewSafeCache_PutThenGetReturnsSameDigest(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	layer, err := random.Layer(512, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)
	origDigest, err := layer.Digest()
	require.NoError(t, err)

	cached, err := wrapped.Put(layer)
	require.NoError(t, err)
	rc, err := cached.Compressed()
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, rc)
	_ = rc.Close()

	got, err := wrapped.Get(origDigest)
	require.NoError(t, err)
	gotDigest, err := got.Digest()
	require.NoError(t, err)
	assert.Equal(t, origDigest, gotDigest)
}

// TestNewSafeCache_ConcurrentCompressedSameLayer stresses concurrent Compressed() on the same
// cached layer; all callers must get valid content without race.
func TestNewSafeCache_ConcurrentCompressedSameLayer(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	layer, err := random.Layer(256, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)

	cached, err := wrapped.Put(layer)
	require.NoError(t, err)

	const numReaders = 6
	errCh := make(chan error, numReaders)
	var wg sync.WaitGroup
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc, err := cached.Compressed()
			if err != nil {
				errCh <- err
				return
			}
			_, err = io.Copy(io.Discard, rc)
			if err != nil {
				errCh <- err
				return
			}
			if err := rc.Close(); err != nil {
				errCh <- err
				return
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}

// TestNewSafeCache_ConcurrentUncompressedSameLayer stresses concurrent Uncompressed() on the same
// cached layer; all callers must get valid content without race.
func TestNewSafeCache_ConcurrentUncompressedSameLayer(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	layer, err := random.Layer(256, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)

	cached, err := wrapped.Put(layer)
	require.NoError(t, err)

	const numReaders = 6
	errCh := make(chan error, numReaders)
	var wg sync.WaitGroup
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc, err := cached.Uncompressed()
			if err != nil {
				errCh <- err
				return
			}
			_, err = io.Copy(io.Discard, rc)
			if err != nil {
				errCh <- err
				return
			}
			if err := rc.Close(); err != nil {
				errCh <- err
				return
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}

// TestNewSafeCache_DeleteThenGetNotFound ensures Delete removes the layer so Get returns ErrNotFound.
func TestNewSafeCache_DeleteThenGetNotFound(t *testing.T) {
	dir := t.TempDir()
	inner := cache.NewFilesystemCache(dir)
	wrapped := NewSafeCache(inner, dir)
	require.NotNil(t, wrapped)

	layer, err := random.Layer(128, "application/vnd.oci.image.layer.v1.tar+gzip")
	require.NoError(t, err)
	digest, err := layer.Digest()
	require.NoError(t, err)

	cached, err := wrapped.Put(layer)
	require.NoError(t, err)
	rc, err := cached.Compressed()
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, rc)
	_ = rc.Close()

	err = wrapped.Delete(digest)
	require.NoError(t, err)

	_, err = wrapped.Get(digest)
	assert.Error(t, err)
	assert.ErrorIs(t, err, cache.ErrNotFound)
}
