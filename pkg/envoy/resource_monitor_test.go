//go:build linux

package envoy

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/testutil"
)

var (
	file = func(data string, mode fs.FileMode) *fstest.MapFile {
		// ensure the data always ends with a \n
		if data != "" && data[len(data)-1] != '\n' {
			data += "\n"
		}
		return &fstest.MapFile{Data: []byte(data), Mode: mode}
	}

	v2Fs = fstest.MapFS{
		"sys/fs/cgroup/test/cgroup.type":            file("domain", 0o644),
		"sys/fs/cgroup/test/cgroup.controllers":     file("memory", 0o444),
		"sys/fs/cgroup/test/cgroup.subtree_control": file("", 0o644),
		"sys/fs/cgroup/test/memory.current":         file("100", 0o644),
		"sys/fs/cgroup/test/memory.max":             file("200", 0o644),

		"proc/1/cgroup": file("0::/test\n", 0o444),
		"proc/2/cgroup": file("0::/test2 (deleted)\n", 0o444),

		"proc/1/mountinfo": file(`
24 30 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw
25 30 0:23 / /sys rw,nosuid,nodev,noexec,relatime shared:6 - sysfs sys rw
33 25 0:28 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot
`[1:], 0o444),
	}

	v1Fs = fstest.MapFS{
		"sys/fs/cgroup/memory/test/memory.usage_in_bytes": file("100", 0o644),
		"sys/fs/cgroup/memory/test/memory.limit_in_bytes": file("200", 0o644),

		"proc/1/cgroup": file(`
1:memory:/test
0::/test
`[1:], 0o444),
		"proc/1/mountinfo": file(`
26 31 0:24 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
27 31 0:5 / /proc rw,nosuid,nodev,noexec,relatime shared:14 - proc proc rw
31 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw,errors=remount-ro
35 26 0:29 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:9 - tmpfs tmpfs ro,mode=755
40 35 0:34 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:15 - cgroup cgroup rw,memory
`[1:], 0o444),
	}

	v1ContainerFs = fstest.MapFS{
		"sys/fs/cgroup/memory/test/memory.usage_in_bytes": file("100", 0o644),
		"sys/fs/cgroup/memory/test/memory.limit_in_bytes": file("200", 0o644),

		"proc/1/cgroup": file(`
1:memory:/test
0::/test
`[1:], 0o444),
		"proc/1/mountinfo": file(`
1574 1573 0:138 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1578 1573 0:133 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
1579 1578 0:141 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,mode=755
1586 1579 0:39 /test /sys/fs/cgroup/memory ro,nosuid,nodev,noexec,relatime master:20 - cgroup cgroup rw,memory
1311 1574 0:138 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw
`[1:], 0o444),
	}

	hybridFs = fstest.MapFS{
		"sys/fs/cgroup/memory/test/memory.usage_in_bytes":   file("100", 0o644),
		"sys/fs/cgroup/memory/test/memory.limit_in_bytes":   file("200", 0o644),
		"sys/fs/cgroup/unified/test/cgroup.type":            file("domain", 0o644),
		"sys/fs/cgroup/unified/test/cgroup.controllers":     file("memory", 0o444),
		"sys/fs/cgroup/unified/test/cgroup.subtree_control": file("", 0o644),
		"sys/fs/cgroup/unified/test/memory.current":         file("100", 0o644),
		"sys/fs/cgroup/unified/test/memory.max":             file("200", 0o644),

		"proc/1/cgroup": file(`
1:memory:/test
0::/test
`[1:], 0o444),
		"proc/1/mountinfo": file(`
26 31 0:24 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
27 31 0:5 / /proc rw,nosuid,nodev,noexec,relatime shared:14 - proc proc rw
35 26 0:29 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:9 - tmpfs tmpfs ro,mode=755
36 35 0:30 / /sys/fs/cgroup/unified rw,nosuid,nodev,noexec,relatime shared:10 - cgroup2 cgroup2 rw,nsdelegate
46 35 0:40 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:21 - cgroup cgroup rw,memory
`[1:], 0o444),
	}

	with = func(dest, src fstest.MapFS) fstest.MapFS {
		dest = maps.Clone(dest)
		for k, v := range src {
			dest[k] = v
		}
		return dest
	}

	without = func(fs fstest.MapFS, keys ...string) fstest.MapFS {
		fs = maps.Clone(fs)
		for _, k := range keys {
			delete(fs, k)
		}
		return fs
	}
)

func TestCgroupV2Driver(t *testing.T) {
	d := cgroupV2Driver{
		root: "sys/fs/cgroup",
		fs:   v2Fs,
	}
	t.Run("Path", func(t *testing.T) {
		assert.Equal(t, "sys/fs/cgroup", d.Path("test", RootPath))
		assert.Equal(t, "sys/fs/cgroup/test/memory.current", d.Path("test", MemoryUsagePath))
		assert.Equal(t, "sys/fs/cgroup/test/memory.max", d.Path("test", MemoryLimitPath))
		assert.Equal(t, "", d.Path("test", CgroupFilePath(0xF00)))
	})

	t.Run("CgroupForPid", func(t *testing.T) {
		cgroup, err := d.CgroupForPid(1)
		assert.NoError(t, err)
		assert.Equal(t, "/test", cgroup)

		cgroup, err = d.CgroupForPid(2)
		assert.NoError(t, err)
		assert.Equal(t, "/test2", cgroup)

		_, err = d.CgroupForPid(12345)
		assert.Error(t, err)
	})

	t.Run("MemoryUsage", func(t *testing.T) {
		cases := []struct {
			fs    fstest.MapFS
			err   string
			usage uint64
		}{
			0: {
				fs:    v2Fs,
				usage: 100,
			},
			1: {
				fs: with(v2Fs, fstest.MapFS{
					"sys/fs/cgroup/test/memory.current": file("invalid", 0o644),
				}),
				err: "strconv.ParseUint: parsing \"invalid\": invalid syntax",
			},
			2: {
				fs:  without(v2Fs, "sys/fs/cgroup/test/memory.current"),
				err: "open sys/fs/cgroup/test/memory.current: file does not exist",
			},
		}

		for i, c := range cases {
			t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
				driver := cgroupV2Driver{
					root: "sys/fs/cgroup",
					fs:   c.fs,
				}
				usage, err := driver.MemoryUsage("test")
				if c.err == "" {
					assert.NoError(t, err)
					assert.Equal(t, c.usage, usage)
				} else {
					assert.EqualError(t, err, c.err)
				}
			})
		}
	})

	t.Run("MemoryLimit", func(t *testing.T) {
		cases := []struct {
			fs    fstest.MapFS
			err   string
			limit uint64
		}{
			0: {
				fs:    v2Fs,
				limit: 200,
			},
			1: {
				fs: with(v2Fs, fstest.MapFS{
					"sys/fs/cgroup/test/memory.max": file("max", 0o644),
				}),
				limit: 0,
			},
			2: {
				fs:  without(v2Fs, "sys/fs/cgroup/test/memory.max"),
				err: "open sys/fs/cgroup/test/memory.max: file does not exist",
			},
			3: {
				fs: with(v2Fs, fstest.MapFS{
					"sys/fs/cgroup/test/memory.max": file("invalid", 0o644),
				}),
				err: "strconv.ParseUint: parsing \"invalid\": invalid syntax",
			},
		}

		for i, c := range cases {
			t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
				driver := cgroupV2Driver{
					root: "sys/fs/cgroup",
					fs:   c.fs,
				}
				limit, err := driver.MemoryLimit("test")
				if c.err == "" {
					assert.NoError(t, err)
					assert.Equal(t, c.limit, limit)
				} else {
					assert.EqualError(t, err, c.err)
				}
			})
		}
	})

	t.Run("Validate", func(t *testing.T) {
		cases := []struct {
			fs   fstest.MapFS
			root string // optional
			err  string
		}{
			0: {fs: v2Fs},
			1: {fs: hybridFs, root: "sys/fs/cgroup/unified"},
			2: {
				fs: with(v2Fs, fstest.MapFS{
					"sys/fs/cgroup/test/cgroup.type": file("threaded", 0o644),
				}),
				err: "not a domain cgroup",
			},
			3: {
				fs: with(v2Fs, fstest.MapFS{
					"sys/fs/cgroup/test/cgroup.subtree_control": file("cpu", 0o644),
				}),
				err: "not a leaf cgroup",
			},
			4: {
				fs: with(v2Fs, fstest.MapFS{
					"sys/fs/cgroup/test/cgroup.controllers": file("cpu io", 0o444),
				}),
				err: "memory controller not enabled",
			},
			5: {
				fs:  without(v2Fs, "sys/fs/cgroup/test/cgroup.controllers"),
				err: "open sys/fs/cgroup/test/cgroup.controllers: file does not exist",
			},
			6: {
				fs:  without(v2Fs, "sys/fs/cgroup/test/cgroup.type"),
				err: "open sys/fs/cgroup/test/cgroup.type: file does not exist",
			},
			7: {
				fs:  without(v2Fs, "sys/fs/cgroup/test/cgroup.subtree_control"),
				err: "open sys/fs/cgroup/test/cgroup.subtree_control: file does not exist",
			},
		}

		for i, c := range cases {
			t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
				driver := cgroupV2Driver{
					root: "sys/fs/cgroup",
					fs:   c.fs,
				}
				if c.root != "" {
					driver.root = c.root
				}
				err := driver.Validate("test")
				if c.err == "" {
					assert.NoError(t, err)
				} else {
					assert.EqualError(t, err, c.err)
				}
			})
		}
	})
}

func TestCgroupV1Driver(t *testing.T) {
	d := cgroupV1Driver{
		root: "sys/fs/cgroup",
		fs:   v1Fs,
	}
	t.Run("Path", func(t *testing.T) {
		assert.Equal(t, "sys/fs/cgroup", d.Path("test", RootPath))
		assert.Equal(t, "sys/fs/cgroup/memory/test/memory.usage_in_bytes", d.Path("test", MemoryUsagePath))
		assert.Equal(t, "sys/fs/cgroup/memory/test/memory.limit_in_bytes", d.Path("test", MemoryLimitPath))
		assert.Equal(t, "", d.Path("test", CgroupFilePath(0xF00)))
	})

	t.Run("CgroupForPid", func(t *testing.T) {
		cgroup, err := d.CgroupForPid(1)
		assert.NoError(t, err)
		assert.Equal(t, "/test", cgroup)

		_, err = d.CgroupForPid(12345)
		assert.Error(t, err)
	})

	t.Run("MemoryUsage", func(t *testing.T) {
		cases := []struct {
			fs    fstest.MapFS
			err   string
			usage uint64
		}{
			0: {
				fs:    v1Fs,
				usage: 100,
			},
			1: {
				fs: with(v1Fs, fstest.MapFS{
					"sys/fs/cgroup/memory/test/memory.usage_in_bytes": file("invalid", 0o644),
				}),
				err: "strconv.ParseUint: parsing \"invalid\": invalid syntax",
			},
			2: {
				fs:  without(v1Fs, "sys/fs/cgroup/memory/test/memory.usage_in_bytes"),
				err: "open sys/fs/cgroup/memory/test/memory.usage_in_bytes: file does not exist",
			},
		}

		for i, c := range cases {
			t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
				driver := cgroupV1Driver{
					root: "sys/fs/cgroup",
					fs:   c.fs,
				}
				usage, err := driver.MemoryUsage("test")
				if c.err == "" {
					assert.NoError(t, err)
					assert.Equal(t, c.usage, usage)
				} else {
					assert.EqualError(t, err, c.err)
				}
			})
		}
	})

	t.Run("MemoryLimit", func(t *testing.T) {
		cases := []struct {
			fs    fstest.MapFS
			err   string
			limit uint64
		}{
			0: {
				fs:    v1Fs,
				limit: 200,
			},
			1: {
				fs: with(v1Fs, fstest.MapFS{
					"sys/fs/cgroup/memory/test/memory.limit_in_bytes": file("max", 0o644),
				}),
				limit: 0,
			},
			2: {
				fs: with(v1Fs, fstest.MapFS{
					"sys/fs/cgroup/memory/test/memory.limit_in_bytes": file("invalid", 0o644),
				}),
				err: "strconv.ParseUint: parsing \"invalid\": invalid syntax",
			},
			3: {
				fs:  without(v1Fs, "sys/fs/cgroup/memory/test/memory.limit_in_bytes"),
				err: "open sys/fs/cgroup/memory/test/memory.limit_in_bytes: file does not exist",
			},
		}

		for i, c := range cases {
			t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
				driver := cgroupV1Driver{
					root: "sys/fs/cgroup",
					fs:   c.fs,
				}
				limit, err := driver.MemoryLimit("test")
				if c.err == "" {
					assert.NoError(t, err)
					assert.Equal(t, c.limit, limit)
				} else {
					assert.EqualError(t, err, c.err)
				}
			})
		}
	})

	t.Run("Validate", func(t *testing.T) {
		cases := []struct {
			fs  fstest.MapFS
			err string
		}{
			0: {fs: v1Fs},
			1: {fs: v1ContainerFs},
			2: {fs: hybridFs},
			3: {
				fs: without(v1Fs,
					"sys/fs/cgroup/memory/test/memory.usage_in_bytes",
					"sys/fs/cgroup/memory/test/memory.limit_in_bytes",
				),
				err: "memory controller not enabled",
			},
		}

		for i, c := range cases {
			t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
				driver := cgroupV1Driver{
					root: "sys/fs/cgroup",
					fs:   c.fs,
				}
				err := driver.Validate("test")
				if c.err == "" {
					assert.NoError(t, err)
				} else {
					assert.EqualError(t, err, c.err)
				}
			})
		}
	})

	t.Run("Container FS", func(t *testing.T) {
		driver := cgroupV1Driver{
			root: "sys/fs/cgroup",
			fs:   v1ContainerFs,
		}
		cgroup, err := driver.CgroupForPid(1)
		assert.NoError(t, err)
		assert.Equal(t, "/", cgroup)
	})

	t.Run("Hybrid FS", func(t *testing.T) {
		driver := cgroupV1Driver{
			root: "sys/fs/cgroup",
			fs:   hybridFs,
		}
		cgroup, err := driver.CgroupForPid(1)
		assert.NoError(t, err)
		assert.Equal(t, "/test", cgroup)

		driver2 := cgroupV2Driver{
			root: "sys/fs/cgroup/unified",
			fs:   hybridFs,
		}
		cgroup, err = driver2.CgroupForPid(1)
		assert.NoError(t, err)
		assert.Equal(t, "/test", cgroup)
	})
}

func TestFindMountpoint(t *testing.T) {
	withActualPid := func(fs fstest.MapFS) fstest.MapFS {
		fs = maps.Clone(fs)
		fs[fmt.Sprintf("proc/%d/cgroup", os.Getpid())] = fs["proc/1/cgroup"]
		fs[fmt.Sprintf("proc/%d/mountinfo", os.Getpid())] = fs["proc/1/mountinfo"]
		return fs
	}
	cases := []struct {
		fsys fs.FS

		mountpoint string
		isV2       bool
		err        string
	}{
		0: {
			fsys:       withActualPid(v2Fs),
			mountpoint: "sys/fs/cgroup",
			isV2:       true,
		},
		1: {
			fsys:       withActualPid(v1Fs),
			mountpoint: "sys/fs/cgroup",
			isV2:       false,
		},
		2: {
			fsys:       withActualPid(hybridFs),
			mountpoint: "sys/fs/cgroup/unified",
			isV2:       true,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			mountpoint, isV2, err := findMountpoint(c.fsys)
			if c.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, c.mountpoint, mountpoint)
				assert.Equal(t, c.isV2, isV2)
			} else {
				assert.EqualError(t, err, c.err)
			}
		})
	}
}

type hybridTestFS struct {
	base    fstest.MapFS
	tempDir string
}

var _ fs.FS = (*hybridTestFS)(nil)

func (fs *hybridTestFS) Open(name string) (fs.File, error) {
	switch base := path.Base(name); base {
	case "memory.current", "memory.max":
		return os.Open(filepath.Join(fs.tempDir, ".fs", base))
	}
	return fs.base.Open(name)
}

func (fs *hybridTestFS) ReadFile(name string) ([]byte, error) {
	switch base := path.Base(name); base {
	case "memory.current", "memory.max":
		return os.ReadFile(filepath.Join(fs.tempDir, ".fs", base))
	}
	return fs.base.ReadFile(name)
}

func (fs *hybridTestFS) Stat(name string) (fs.FileInfo, error) {
	switch base := path.Base(name); base {
	case "memory.current", "memory.max":
		return os.Stat(filepath.Join(fs.tempDir, ".fs", base))
	}
	return fs.base.Stat(name)
}

type pathOverrideDriver struct {
	CgroupDriver
	overrides map[CgroupFilePath]string
}

var _ CgroupDriver = (*pathOverrideDriver)(nil)

func (d *pathOverrideDriver) Path(name string, path CgroupFilePath) string {
	if override, ok := d.overrides[path]; ok {
		return override
	}
	return d.CgroupDriver.Path(name, path)
}

func TestSharedResourceMonitor(t *testing.T) {
	// set shorter intervals for testing
	var prevInitialDelay, prevMinInterval, prevMaxInterval time.Duration
	monitorInitialTickDelay, prevInitialDelay = 0, monitorInitialTickDelay
	monitorMaxTickInterval, prevMaxInterval = 100*time.Millisecond, monitorMaxTickInterval
	monitorMinTickInterval, prevMinInterval = 10*time.Millisecond, monitorMinTickInterval
	t.Cleanup(func() {
		monitorInitialTickDelay = prevInitialDelay
		monitorMaxTickInterval = prevMaxInterval
		monitorMinTickInterval = prevMinInterval
	})

	testEnvoyPid := 99
	tempDir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(tempDir, ".fs"), 0o777))

	testMemoryCurrentPath := filepath.Join(tempDir, ".fs/memory.current")
	testMemoryMaxPath := filepath.Join(tempDir, ".fs/memory.max")

	updateMemoryCurrent := func(value string) {
		t.Log("updating memory.current to", value)
		f, err := os.OpenFile(testMemoryCurrentPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		require.NoError(t, err)
		f.WriteString(value)
		require.NoError(t, f.Close())
	}

	updateMemoryMax := func(value string) {
		t.Log("updating memory.max to", value)
		f, err := os.OpenFile(testMemoryMaxPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		require.NoError(t, err)
		f.WriteString(value)
		require.NoError(t, f.Close())
	}

	updateMemoryCurrent("100")
	updateMemoryMax("200")

	driver := &pathOverrideDriver{
		CgroupDriver: &cgroupV2Driver{
			root: "sys/fs/cgroup",
			fs: &hybridTestFS{
				base: with(v2Fs, fstest.MapFS{
					fmt.Sprintf("proc/%d/cgroup", os.Getpid()):     v2Fs["proc/1/cgroup"],
					fmt.Sprintf("proc/%d/mountinfo", os.Getpid()):  v2Fs["proc/1/mountinfo"],
					fmt.Sprintf("proc/%d/cgroup", testEnvoyPid):    v2Fs["proc/1/cgroup"],
					fmt.Sprintf("proc/%d/mountinfo", testEnvoyPid): v2Fs["proc/1/mountinfo"],
				}),
				tempDir: tempDir,
			},
		},
		overrides: map[CgroupFilePath]string{
			MemoryUsagePath: testMemoryCurrentPath,
			MemoryLimitPath: testMemoryMaxPath,
		},
	}

	configSrc := config.NewStaticSource(&config.Config{})
	monitor, err := NewSharedResourceMonitor(context.Background(), configSrc, tempDir, WithCgroupDriver(driver))
	require.NoError(t, err)

	readMemorySaturation := func(t assert.TestingT) string {
		f, err := os.ReadFile(filepath.Join(tempDir, "resource_monitor/memory/cgroup_memory_saturation"))
		assert.NoError(t, err)
		return string(f)
	}

	assert.Equal(t, "0", readMemorySaturation(t))

	ctx, ca := context.WithCancel(context.Background())

	errC := make(chan error)
	go func() {
		defer close(errC)
		errC <- monitor.Run(ctx, testEnvoyPid)
	}()

	timeout := 1 * time.Second
	interval := 10 * time.Millisecond
	// 100/200
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "0.500000", readMemorySaturation(c))
	}, timeout, interval)

	// 150/200
	updateMemoryCurrent("150")
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "0.750000", readMemorySaturation(c))
	}, timeout, interval)

	// 150/300
	updateMemoryMax("300")
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "0.500000", readMemorySaturation(c))
	}, timeout, interval)

	// 150/unlimited
	updateMemoryMax("max")
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "0.000000", readMemorySaturation(c))
	}, timeout, interval)

	// 150/145 (over limit)
	updateMemoryMax("145")
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "1.000000", readMemorySaturation(c))
	}, timeout, interval)

	// 150/150
	updateMemoryMax("150")
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "1.000000", readMemorySaturation(c))
	}, timeout, interval)

	configSrc.SetConfig(ctx, &config.Config{
		Options: &config.Options{
			RuntimeFlags: config.RuntimeFlags{
				config.RuntimeFlagEnvoyResourceManager: false,
			},
		},
	})

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "0.000000", readMemorySaturation(c))
	}, timeout, interval)

	configSrc.SetConfig(ctx, &config.Config{
		Options: &config.Options{
			RuntimeFlags: config.RuntimeFlags{
				config.RuntimeFlagEnvoyResourceManager: true,
			},
		},
	})

	updateMemoryMax("150")
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "1.000000", readMemorySaturation(c))
	}, timeout, interval)

	ca()
	assert.ErrorIs(t, <-errC, context.Canceled)

	// test deletion of memory.max
	updateMemoryCurrent("150")
	updateMemoryMax("300")
	monitor, err = NewSharedResourceMonitor(context.Background(), configSrc, tempDir, WithCgroupDriver(driver))
	require.NoError(t, err)

	errC = make(chan error)
	go func() {
		defer close(errC)
		errC <- monitor.Run(context.Background(), testEnvoyPid)
	}()

	// 150/300
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, "0.500000", readMemorySaturation(c))
	}, timeout, interval)

	require.NoError(t, os.Remove(testMemoryMaxPath))

	assert.EqualError(t, <-errC, "memory limit watcher stopped")
}

func TestBootstrapConfig(t *testing.T) {
	b := envoyconfig.New("localhost:1111", "localhost:2222", "localhost:3333", filemgr.NewManager(), nil, true)
	testEnvoyPid := 99
	tempDir := t.TempDir()
	monitor, err := NewSharedResourceMonitor(context.Background(), config.NewStaticSource(nil), tempDir, WithCgroupDriver(&cgroupV2Driver{
		root: "sys/fs/cgroup",
		fs: &hybridTestFS{
			base: with(v2Fs, fstest.MapFS{
				fmt.Sprintf("proc/%d/cgroup", os.Getpid()):     v2Fs["proc/1/cgroup"],
				fmt.Sprintf("proc/%d/mountinfo", os.Getpid()):  v2Fs["proc/1/mountinfo"],
				fmt.Sprintf("proc/%d/cgroup", testEnvoyPid):    v2Fs["proc/1/cgroup"],
				fmt.Sprintf("proc/%d/mountinfo", testEnvoyPid): v2Fs["proc/1/mountinfo"],
			}),
			tempDir: tempDir,
		},
	}))
	require.NoError(t, err)

	bootstrap, err := b.BuildBootstrap(context.Background(), &config.Config{
		Options: &config.Options{
			EnvoyAdminAddress: "localhost:9901",
		},
	}, false)
	assert.NoError(t, err)

	monitor.ApplyBootstrapConfig(bootstrap)

	testutil.AssertProtoJSONEqual(t, fmt.Sprintf(`
		{
			"actions": [
				{
					"name": "envoy.overload_actions.shrink_heap",
					"triggers": [
						{
							"name": "envoy.resource_monitors.injected_resource",
							"threshold": {
								"value": 0.9
							}
						}
					]
				},
				{
					"name": "envoy.overload_actions.reduce_timeouts",
					"triggers": [
						{
							"name": "envoy.resource_monitors.injected_resource",
							"scaled": {
								"saturationThreshold": 0.95,
								"scalingThreshold": 0.85
							}
						}
					],
					"typedConfig": {
						"@type": "type.googleapis.com/envoy.config.overload.v3.ScaleTimersOverloadActionConfig",
						"timerScaleFactors": [
							{
								"minScale": {
									"value": 50
								},
								"timer": "HTTP_DOWNSTREAM_CONNECTION_IDLE"
							}
						]
					}
				},
				{
					"name": "envoy.overload_actions.reset_high_memory_stream",
					"triggers": [
						{
							"name": "envoy.resource_monitors.injected_resource",
							"scaled": {
								"saturationThreshold": 0.98,
								"scalingThreshold": 0.9
							}
						}
					]
				},
				{
					"name": "envoy.overload_actions.stop_accepting_connections",
					"triggers": [
						{
							"name": "envoy.resource_monitors.injected_resource",
							"threshold": {
								"value": 0.95
							}
						}
					]
				},
				{
					"name": "envoy.overload_actions.disable_http_keepalive",
					"triggers": [
						{
							"name": "envoy.resource_monitors.injected_resource",
							"threshold": {
								"value": 0.98
							}
						}
					]
				},
				{
					"name": "envoy.overload_actions.stop_accepting_requests",
					"triggers": [
						{
							"name": "envoy.resource_monitors.injected_resource",
							"threshold": {
								"value": 0.99
							}
						}
					]
				}
			],
			"bufferFactoryConfig": {
				"minimumAccountToTrackPowerOfTwo": 20
			},
			"resourceMonitors": [
				{
					"name": "envoy.resource_monitors.global_downstream_max_connections",
					"typedConfig": {
						"@type": "type.googleapis.com/envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig",
						"maxActiveDownstreamConnections": "50000"
					}
				},
				{
					"name": "envoy.resource_monitors.injected_resource",
					"typedConfig": {
						"@type": "type.googleapis.com/envoy.extensions.resource_monitors.injected_resource.v3.InjectedResourceConfig",
						"filename": "%s/resource_monitor/memory/cgroup_memory_saturation"
					}
				}
			]
		}
		`, tempDir), bootstrap.OverloadManager)
}

func TestComputeScaledTickInterval(t *testing.T) {
	cases := []struct {
		saturation float64
		expected   time.Duration
	}{
		0: {
			saturation: 0.0,
			expected:   10000 * time.Millisecond,
		},
		1: {
			saturation: 1.0,
			expected:   250 * time.Millisecond,
		},
		2: {
			saturation: 0.5,
			expected:   5125 * time.Millisecond,
		},
		3: {
			// duration should round to the nearest millisecond
			saturation: 0.3333,
			expected:   6750 * time.Millisecond,
		},
		4: {
			saturation: -1.0,
			expected:   10000 * time.Millisecond,
		},
		5: {
			// saturation > 1 should be clamped to 1
			saturation: 1.5,
			expected:   250 * time.Millisecond,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			assert.Equal(t, c.expected, computeScaledTickInterval(c.saturation))
		})
	}
}
