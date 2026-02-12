package core

import (
	"sync"
	"sync/atomic"

	uv "github.com/charmbracelet/ultraviolet"
)

type buffer struct {
	uv.ScreenBuffer
	width, height int
	mu            sync.Mutex
	_             [24]byte // pad to cache line
}

type DoubleBuffer struct {
	buffers [2]buffer
	back    *buffer
	front   atomic.Pointer[buffer]
}

func NewDoubleBuffer() *DoubleBuffer {
	db := &DoubleBuffer{
		buffers: [2]buffer{
			{
				ScreenBuffer: uv.NewScreenBuffer(0, 0),
			},
			{
				ScreenBuffer: uv.NewScreenBuffer(0, 0),
			},
		},
	}
	db.back = &db.buffers[0]
	db.back.mu.Lock()
	db.front.Store(&db.buffers[1])
	return db
}

func (db *DoubleBuffer) UpdateView(width, height int, drawable uv.Drawable) {
	back := db.back
	if back.width != width || back.height != height {
		back.width = width
		back.height = height
		back.ScreenBuffer = uv.NewScreenBuffer(width, height)
	}
	drawable.Draw(back, uv.Rect(0, 0, back.width, back.height))
	db.swap()
}

func (db *DoubleBuffer) Draw(scr uv.Screen, area uv.Rectangle) {
	front := db.front.Load()
	front.mu.Lock()
	defer front.mu.Unlock()
	front.Draw(scr, area)
}

func (db *DoubleBuffer) swap() {
	db.back.mu.Unlock()              // unlock the current back buffer
	db.back = db.front.Swap(db.back) // swap the front and back buffers
	db.back.mu.Lock()                // wait for the previous frame to finish rendering
}
