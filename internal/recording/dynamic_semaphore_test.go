package recording_test

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/recording"
)

func TestDynamicSemaphoreConformance(t *testing.T) {
	t.Parallel()
	impls := map[string]func(int) recording.DynamicSemaphore{
		"reservation": recording.NewReservationSemaphore,
	}

	for name, newSem := range impls {
		t.Run(name, func(t *testing.T) {
			t.Run("basic acquire and release", func(t *testing.T) {
				s := newSem(3)

				assert.True(t, s.TryAcquire())
				assert.True(t, s.TryAcquire())
				assert.True(t, s.TryAcquire())
				assert.False(t, s.TryAcquire(), "should reject when at limit")

				s.Release()
				assert.True(t, s.TryAcquire(), "should allow after release")
			})

			t.Run("resize down with no active slots", func(t *testing.T) {
				s := newSem(8)
				s.Resize(4)

				for range 4 {
					assert.True(t, s.TryAcquire())
				}
				assert.False(t, s.TryAcquire(), "should reject at new lower limit")

				for range 4 {
					s.Release()
				}
			})

			// verifies the new limit is enforced after all old holders release.
			t.Run("resize down with all slots held", func(t *testing.T) {
				s := newSem(8)

				for range 8 {
					assert.True(t, s.TryAcquire())
				}
				s.Resize(6)

				for range 8 {
					s.Release()
				}
				for range 6 {
					assert.True(t, s.TryAcquire())
				}
				assert.False(t, s.TryAcquire(), "should enforce new limit after full turnover")

				for range 6 {
					s.Release()
				}
			})

			t.Run("resize down then up", func(t *testing.T) {
				s := newSem(8)

				for range 8 {
					assert.True(t, s.TryAcquire())
				}
				s.Resize(4)
				s.Resize(6)

				for range 8 {
					s.Release()
				}
				for range 6 {
					assert.True(t, s.TryAcquire())
				}
				assert.False(t, s.TryAcquire())

				for range 6 {
					s.Release()
				}
			})

			// resize while all slots are held must not panic or drift.
			t.Run("repeated resize cycles", func(t *testing.T) {
				s := newSem(8)

				for range 8 {
					assert.True(t, s.TryAcquire())
				}
				for range 50 {
					s.Resize(4)
					s.Resize(8)
				}

				for range 8 {
					s.Release()
				}
				for range 8 {
					assert.True(t, s.TryAcquire())
				}
				assert.False(t, s.TryAcquire())

				for range 8 {
					s.Release()
				}
			})

			t.Run("resize down with partially held slots", func(t *testing.T) {
				s := newSem(8)

				for range 5 {
					assert.True(t, s.TryAcquire())
				}
				s.Resize(3)

				for range 5 {
					s.Release()
				}
				for range 3 {
					assert.True(t, s.TryAcquire())
				}
				assert.False(t, s.TryAcquire())

				for range 3 {
					s.Release()
				}
			})

			t.Run("resize up after full release", func(t *testing.T) {
				s := newSem(2)

				assert.True(t, s.TryAcquire())
				assert.True(t, s.TryAcquire())
				assert.False(t, s.TryAcquire())

				s.Release()
				s.Release()
				s.Resize(4)

				for range 4 {
					assert.True(t, s.TryAcquire())
				}
				assert.False(t, s.TryAcquire(), "should reject at new limit")

				for range 4 {
					s.Release()
				}
			})
		})
	}
}

func TestDynamicSemaphoreConcurrency(t *testing.T) {
	impls := map[string]func(int) recording.DynamicSemaphore{
		"reservation": recording.NewReservationSemaphore,
	}

	for name, newSem := range impls {
		t.Run(name, func(t *testing.T) {
			t.Run("concurrent acquires never exceed limit", func(t *testing.T) {
				const limit = 5
				const goroutines = 100
				const iterations = 1000

				s := newSem(limit)
				var peak atomic.Int64
				var held atomic.Int64

				var wg sync.WaitGroup
				for range goroutines {
					wg.Go(func() {
						for range iterations {
							if s.TryAcquire() {
								cur := held.Add(1)
								for {
									p := peak.Load()
									if cur <= p || peak.CompareAndSwap(p, cur) {
										break
									}
								}
								held.Add(-1)
								s.Release()
							}
						}
					})
				}
				wg.Wait()

				require.LessOrEqual(t, peak.Load(), int64(limit),
					"observed concurrency exceeded the limit")
			})

			t.Run("concurrent acquire and release is balanced", func(t *testing.T) {
				const limit = 8
				const goroutines = 50
				const iterations = 500

				s := newSem(limit)

				var wg sync.WaitGroup
				wg.Add(goroutines)
				for range goroutines {
					go func() {
						defer wg.Done()
						for range iterations {
							if s.TryAcquire() {
								s.Release()
							}
						}
					}()
				}
				wg.Wait()

				for range limit {
					require.True(t, s.TryAcquire(), "slot should be available after balanced acquire/release")
				}
				assert.False(t, s.TryAcquire())

				for range limit {
					s.Release()
				}
			})

			// concurrent toggling must yield consistent results
			t.Run("concurrent resize while acquiring", func(t *testing.T) {
				const goroutines = 50
				const iterations = 500

				s := newSem(8)

				var wg sync.WaitGroup
				wg.Add(goroutines + 1)

				go func() {
					defer wg.Done()
					for i := range iterations {
						if i%2 == 0 {
							s.Resize(4)
						} else {
							s.Resize(8)
						}
					}
					s.Resize(8)
				}()

				for range goroutines {
					go func() {
						defer wg.Done()
						for range iterations {
							if s.TryAcquire() {
								s.Release()
							}
						}
					}()
				}
				wg.Wait()

				for range 8 {
					require.True(t, s.TryAcquire())
				}
				assert.False(t, s.TryAcquire())

				for range 8 {
					s.Release()
				}
			})

			t.Run("no panic under concurrent resize down and release", func(t *testing.T) {
				const limit = 8

				s := newSem(limit)
				for range limit {
					require.True(t, s.TryAcquire())
				}

				var wg sync.WaitGroup
				wg.Add(limit + 1)

				go func() {
					defer wg.Done()
					for i := range 50 {
						s.Resize(2 + (i % 7))
					}
					s.Resize(limit)
				}()

				for range limit {
					go func() {
						defer wg.Done()
						s.Release()
					}()
				}
				wg.Wait()

				require.True(t, s.TryAcquire())
				s.Release()
			})

			t.Run("starvation: held at limit still allows progress on release", func(t *testing.T) {
				const limit = 4
				s := newSem(limit)

				for range limit {
					require.True(t, s.TryAcquire())
				}

				var successes atomic.Int64
				var stop atomic.Bool
				var wg sync.WaitGroup
				for range limit {
					wg.Go(func() {
						for !stop.Load() {
							if s.TryAcquire() {
								successes.Add(1)
								s.Release()
							}
						}
					})
				}

				s.Release()

				for successes.Load() < 10 {
				}

				stop.Store(true)
				wg.Wait()

				require.GreaterOrEqual(t, successes.Load(), int64(10),
					"spinners should have made progress after a slot was released")
			})
		})
	}
}
