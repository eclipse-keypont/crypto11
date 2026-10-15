// SPDX-FileCopyrightText: 2017 Google Inc.
// SPDX-FileCopyrightText: 2026 Thales Group
// SPDX-FileCopyrightText: 2026 The Eclipse Foundation KeyPont project maintainers
// SPDX-License-Identifier: Apache-2.0
//
// Vendored into crypto11 from github.com/thales-e-security/pool@v0.0.2, itself
// extracted from vitess.io/vitess; see internal/pool/README.md for provenance.
// Modified by Duncan Jones to reduce the number of external dependencies.

// Package pool provides functionality to manage and reuse resources
// like connections.
package pool

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrClosed is returned if ResourcePool is used when it's closed.
	ErrClosed = errors.New("resource pool is closed")

	// ErrTimeout is returned if a resource get times out.
	ErrTimeout = errors.New("resource pool timed out")

	prefillTimeout = 30 * time.Second
)

// Factory is a function that can be used to create a resource.
type Factory func() (Resource, error)

// Resource defines the interface that every resource must provide.
// Thread synchronization between Close() and IsClosed()
// is the responsibility of the caller.
type Resource interface {
	Close()
}

// ResourcePool allows you to use a pool of resources.
type ResourcePool struct {
	// stats
	available  AtomicInt64
	active     AtomicInt64
	inUse      AtomicInt64
	waitCount  AtomicInt64
	waitTime   AtomicDuration
	idleClosed AtomicInt64
	idleReused AtomicInt64

	capacity    AtomicInt64
	idleTimeout AtomicDuration

	resources chan resourceWrapper
	factory   Factory
	idleTimer *Timer
}

type resourceWrapper struct {
	resource Resource
	timeUsed time.Time
}

// NewResourcePool creates a new ResourcePool pool.
// capacity is the number of possible resources in the pool:
// there can be up to 'capacity' of these at a given time.
// maxCap specifies the extent to which the pool can be resized
// in the future through the SetCapacity function.
// You cannot resize the pool beyond maxCap.
// If a resource is unused beyond idleTimeout, it's replaced
// with a new one.
// An idleTimeout of 0 means that there is no timeout.
// A non-zero value of prefillParallelism causes the pool to be pre-filled.
// The value specifies how many resources can be opened in parallel.
func NewResourcePool(factory Factory, capacity, maxCap int, idleTimeout time.Duration, prefillParallelism int) *ResourcePool {
	if capacity <= 0 || maxCap <= 0 || capacity > maxCap {
		panic(errors.New("invalid/out of range capacity"))
	}
	rp := &ResourcePool{
		resources: make(chan resourceWrapper, maxCap),
		factory:   factory,
	}
	rp.available.Set(int64(capacity))
	rp.capacity.Set(int64(capacity))
	rp.idleTimeout.Set(idleTimeout)
	for i := 0; i < capacity; i++ {
		rp.resources <- resourceWrapper{}
	}

	ctx, cancel := context.WithTimeout(context.TODO(), prefillTimeout)
	defer cancel()
	if prefillParallelism != 0 {
		sem := NewSemaphore(prefillParallelism, 0 /* timeout */)
		var wg sync.WaitGroup
		for i := 0; i < capacity; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = sem.Acquire()
				defer sem.Release()

				// If context has expired, give up.
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Prefill exists to open capacity resources up front, so it
				// must not be served by the idle-reuse path: reusing the one
				// resource it just opened would leave the pool holding a
				// single resource however large it was created.
				r, err := rp.get(ctx, false)
				if err != nil {
					return
				}
				rp.Put(r)
			}()
		}
		wg.Wait()
	}

	if idleTimeout != 0 {
		rp.idleTimer = NewTimer(idleTimeout / 10)
		rp.idleTimer.Start(rp.closeIdleResources)
	}
	return rp
}

// Close empties the pool calling Close on all its resources.
// You can call Close while there are outstanding resources.
// It waits for all resources to be returned (Put).
// After a Close, Get is not allowed.
func (rp *ResourcePool) Close() {
	if rp.idleTimer != nil {
		rp.idleTimer.Stop()
	}
	_ = rp.SetCapacity(0)
}

// IsClosed returns true if the resource pool is closed.
func (rp *ResourcePool) IsClosed() (closed bool) {
	return rp.capacity.Get() == 0
}

// closeIdleResources scans the pool for idle resources
func (rp *ResourcePool) closeIdleResources() {
	available := int(rp.Available())
	idleTimeout := rp.IdleTimeout()

	for i := 0; i < available; i++ {
		var wrapper resourceWrapper
		select {
		case wrapper = <-rp.resources:
		default:
			// stop early if we don't get anything new from the pool
			return
		}

		func() {
			defer func() { rp.resources <- wrapper }()

			if wrapper.resource != nil && idleTimeout > 0 && time.Until(wrapper.timeUsed.Add(idleTimeout)) < 0 {
				wrapper.resource.Close()
				rp.idleClosed.Add(1)
				rp.reopenResource(&wrapper)
			}
		}()

	}
}

// Get will return the next available resource. If capacity
// has not been reached, it will create a new one using the factory. Otherwise,
// it will wait till the next resource becomes available or a timeout.
// A timeout of 0 is an indefinite wait.
func (rp *ResourcePool) Get(ctx context.Context) (resource Resource, err error) {
	return rp.get(ctx, true)
}

// get takes a resource from the pool. When reuseIdle is set, an already-open
// resource is preferred over opening a new one; prefill turns it off so that it
// still opens the full complement of resources.
func (rp *ResourcePool) get(ctx context.Context, reuseIdle bool) (resource Resource, err error) {
	// If ctx has already expired, avoid racing with rp's resource channel.
	select {
	case <-ctx.Done():
		return nil, ErrTimeout
	default:
	}

	// Fetch
	var wrapper resourceWrapper
	var ok bool
	select {
	case wrapper, ok = <-rp.resources:
	default:
		startTime := time.Now()
		select {
		case wrapper, ok = <-rp.resources:
		case <-ctx.Done():
			return nil, ErrTimeout
		}
		rp.recordWait(startTime)
	}
	if !ok {
		return nil, ErrClosed
	}

	// The channel is FIFO and the pool is created full of empty entries, so a
	// plain receive hands out the empty entries first: every request would open
	// a fresh resource until the pool was full, even with idle resources queued
	// behind them. Look for an already-open resource before falling back to the
	// factory, so the number of resources open on the token tracks the
	// concurrency actually in flight rather than the number of requests served.
	if wrapper.resource == nil && reuseIdle {
		wrapper = rp.takeIdle(wrapper)
	}

	// Unwrap
	if wrapper.resource == nil {
		wrapper.resource, err = rp.factory()
		if err != nil {
			rp.resources <- resourceWrapper{}
			return nil, err
		}
		rp.active.Add(1)
	} else {
		// The resource was already open, whether it came straight off the
		// channel or was found by takeIdle.
		rp.idleReused.Add(1)
	}
	rp.available.Add(-1)
	rp.inUse.Add(1)
	return wrapper.resource, err
}

// takeIdle looks behind the empty entry just taken from the channel for an
// already-open resource, and returns it in place of that entry. The empty
// entries it passes over are put back, so the pool's capacity is unchanged and
// no resource is lost. If no open resource is found, the entry it was given is
// returned unchanged and the caller opens a new one.
//
// The scan is bounded by the channel's capacity and stops as soon as the
// channel is empty, so it cannot spin: each iteration either takes an entry
// that is not put back until the scan ends, or finds the channel empty.
func (rp *ResourcePool) takeIdle(empty resourceWrapper) resourceWrapper {
	var held []resourceWrapper
	var idle resourceWrapper
	found := false

	for i := 0; i < cap(rp.resources); i++ {
		var candidate resourceWrapper
		var ok bool
		select {
		case candidate, ok = <-rp.resources:
		default:
			ok = false
		}
		if !ok {
			break
		}
		if candidate.resource != nil {
			idle = candidate
			found = true
			break
		}
		held = append(held, candidate)
	}

	// Return everything we passed over, and the empty entry we started with if
	// an open resource took its place. The channel has room for all of them:
	// we removed len(held) entries plus, when found, the idle one.
	for _, w := range held {
		rp.resources <- w
	}
	if found {
		rp.resources <- empty
		return idle
	}
	return empty
}

// Put will return a resource to the pool. For every successful Get,
// a corresponding Put is required. If you no longer need a resource,
// you will need to call Put(nil) instead of returning the closed resource.
// This will cause a new resource to be created in its place.
func (rp *ResourcePool) Put(resource Resource) {
	var wrapper resourceWrapper
	if resource != nil {
		wrapper = resourceWrapper{
			resource: resource,
			timeUsed: time.Now(),
		}
	} else {
		rp.reopenResource(&wrapper)
	}
	select {
	case rp.resources <- wrapper:
	default:
		panic(errors.New("attempt to Put into a full ResourcePool"))
	}
	rp.inUse.Add(-1)
	rp.available.Add(1)
}

func (rp *ResourcePool) reopenResource(wrapper *resourceWrapper) {
	if r, err := rp.factory(); err == nil {
		wrapper.resource = r
		wrapper.timeUsed = time.Now()
	} else {
		wrapper.resource = nil
		rp.active.Add(-1)
	}
}

// SetCapacity changes the capacity of the pool.
// You can use it to shrink or expand, but not beyond
// the max capacity. If the change requires the pool
// to be shrunk, SetCapacity waits till the necessary
// number of resources are returned to the pool.
// A SetCapacity of 0 is equivalent to closing the ResourcePool.
func (rp *ResourcePool) SetCapacity(capacity int) error {
	if capacity < 0 || capacity > cap(rp.resources) {
		return fmt.Errorf("capacity %d is out of range", capacity)
	}

	// Atomically swap new capacity with old, but only
	// if old capacity is non-zero.
	var oldcap int
	for {
		oldcap = int(rp.capacity.Get())
		if oldcap == 0 {
			return ErrClosed
		}
		if oldcap == capacity {
			return nil
		}
		if rp.capacity.CompareAndSwap(int64(oldcap), int64(capacity)) {
			break
		}
	}

	if capacity < oldcap {
		for i := 0; i < oldcap-capacity; i++ {
			wrapper := <-rp.resources
			if wrapper.resource != nil {
				wrapper.resource.Close()
				rp.active.Add(-1)
			}
			rp.available.Add(-1)
		}
	} else {
		for i := 0; i < capacity-oldcap; i++ {
			rp.resources <- resourceWrapper{}
			rp.available.Add(1)
		}
	}
	if capacity == 0 {
		close(rp.resources)
	}
	return nil
}

func (rp *ResourcePool) recordWait(start time.Time) {
	rp.waitCount.Add(1)
	rp.waitTime.Add(time.Since(start))
}

// SetIdleTimeout sets the idle timeout. It can only be used if there was an
// idle timeout set when the pool was created.
func (rp *ResourcePool) SetIdleTimeout(idleTimeout time.Duration) {
	if rp.idleTimer == nil {
		panic("SetIdleTimeout called when timer not initialized")
	}

	rp.idleTimeout.Set(idleTimeout)
	rp.idleTimer.SetInterval(idleTimeout / 10)
}

// StatsJSON returns the stats in JSON format.
func (rp *ResourcePool) StatsJSON() string {
	return fmt.Sprintf(`{"Capacity": %v, "Available": %v, "Active": %v, "InUse": %v, "MaxCapacity": %v, "WaitCount": %v, "WaitTime": %v, "IdleTimeout": %v, "IdleClosed": %v, "IdleReused": %v}`,
		rp.Capacity(),
		rp.Available(),
		rp.Active(),
		rp.InUse(),
		rp.MaxCap(),
		rp.WaitCount(),
		rp.WaitTime().Nanoseconds(),
		rp.IdleTimeout().Nanoseconds(),
		rp.IdleClosed(),
		rp.IdleReused(),
	)
}

// Capacity returns the capacity.
func (rp *ResourcePool) Capacity() int64 {
	return rp.capacity.Get()
}

// Available returns the number of currently unused and available resources.
func (rp *ResourcePool) Available() int64 {
	return rp.available.Get()
}

// Active returns the number of active (i.e. non-nil) resources either in the
// pool or claimed for use
func (rp *ResourcePool) Active() int64 {
	return rp.active.Get()
}

// InUse returns the number of claimed resources from the pool
func (rp *ResourcePool) InUse() int64 {
	return rp.inUse.Get()
}

// MaxCap returns the max capacity.
func (rp *ResourcePool) MaxCap() int64 {
	return int64(cap(rp.resources))
}

// WaitCount returns the total number of waits.
func (rp *ResourcePool) WaitCount() int64 {
	return rp.waitCount.Get()
}

// WaitTime returns the total wait time.
func (rp *ResourcePool) WaitTime() time.Duration {
	return rp.waitTime.Get()
}

// IdleTimeout returns the idle timeout.
func (rp *ResourcePool) IdleTimeout() time.Duration {
	return rp.idleTimeout.Get()
}

// IdleClosed returns the count of resources closed due to idle timeout.
func (rp *ResourcePool) IdleClosed() int64 {
	return rp.idleClosed.Get()
}

// IdleReused returns the count of times an already-open resource was handed out
// in preference to opening a new one.
func (rp *ResourcePool) IdleReused() int64 {
	return rp.idleReused.Get()
}
