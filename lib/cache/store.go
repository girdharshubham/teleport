// Teleport
// Copyright (C) 2025 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cache

import (
	"iter"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/utils/sortcache"
)

// store persists cached resources directly in memory.
<<<<<<< HEAD
type store[T any, I comparable] struct {
	cache   *sortcache.SortCache[T, I]
	indexes map[I]func(T) string
=======
type store[T any] struct {
	cache   *sortcache.SortCache[T]
	indexes map[string]func(T) string
>>>>>>> d6594000e3 (Add auditlog exports to TAG via grpc (#53747))
}

// newStore creates a store that will index the resource
// based on the provided indexes.
<<<<<<< HEAD
func newStore[T any, I comparable](indexes map[I]func(T) string) *store[T, I] {
	return &store[T, I]{
		indexes: indexes,
		cache: sortcache.New(sortcache.Config[T, I]{
=======
func newStore[T any](indexes map[string]func(T) string) *store[T] {
	return &store[T]{
		indexes: indexes,
		cache: sortcache.New(sortcache.Config[T]{
>>>>>>> d6594000e3 (Add auditlog exports to TAG via grpc (#53747))
			Indexes: indexes,
		}),
	}
}

// clear removes all items from the store.
<<<<<<< HEAD
func (s *store[T, I]) clear() error {
=======
func (s *store[T]) clear() error {
>>>>>>> d6594000e3 (Add auditlog exports to TAG via grpc (#53747))
	s.cache.Clear()
	return nil
}

// put adds a new item, or updates an existing item.
<<<<<<< HEAD
func (s *store[T, I]) put(t T) error {
=======
func (s *store[T]) put(t T) error {
>>>>>>> d6594000e3 (Add auditlog exports to TAG via grpc (#53747))
	s.cache.Put(t)
	return nil
}

// delete removes the provided item if any of the indexes match.
<<<<<<< HEAD
func (s *store[T, I]) delete(t T) error {
=======
func (s *store[T]) delete(t T) error {
>>>>>>> d6594000e3 (Add auditlog exports to TAG via grpc (#53747))
	for idx, transform := range s.indexes {
		s.cache.Delete(idx, transform(t))
	}

	return nil
}

// len returns the number of values currently stored.
<<<<<<< HEAD
func (s *store[T, I]) len() int {
=======
func (s *store[T]) len() int {
>>>>>>> d6594000e3 (Add auditlog exports to TAG via grpc (#53747))
	return s.cache.Len()
}

// get returns the item matching the provided index and item,
// or a [trace.NotFoundError] if no match was found.
//
// It is the responsibility of the caller to clone the resource
// before propagating it further.
<<<<<<< HEAD
func (s *store[T, I]) get(index I, key string) (T, error) {
	t, ok := s.cache.Get(index, key)
	if !ok {
		return t, trace.NotFound("no value for key %q in index %v", key, index)
=======
func (s *store[T]) get(index, key string) (T, error) {
	t, ok := s.cache.Get(index, key)
	if !ok {
		return t, trace.NotFound("no value for key %q in index %q", key, index)
>>>>>>> d6594000e3 (Add auditlog exports to TAG via grpc (#53747))
	}

	return t, nil
}

// resources returns an iterator over all items in the provided range
// for the given index in ascending order.
//
// It is the responsibility of the caller to clone the resource
// before propagating it further.
<<<<<<< HEAD
func (s *store[T, I]) resources(index I, start, stop string) iter.Seq[T] {
	return s.cache.Ascend(index, start, stop)
}

// count returns the number of items that exist in the provided range.
func (s *store[T, I]) count(index I, start, stop string) int {
	var n int
	for range s.cache.Ascend(index, start, stop) {
		n++
	}

	return n
}
=======
func (s *store[T]) resources(index, start, stop string) iter.Seq[T] {
	return s.cache.Ascend(index, start, stop)
}
>>>>>>> d6594000e3 (Add auditlog exports to TAG via grpc (#53747))
