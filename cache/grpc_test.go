//go:generate protoc -I ../internal/grpc/cache/ --go_out=plugins=grpc:../internal/grpc/cache/ ../internal/grpc/cache/cache.proto

package cache

import (
	"context"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/grpc/cache"
)

func TestCache_Get_and_Set(t *testing.T) {
	hugeKey := cryptutil.NewRandomStringN(10 << 20)
	dir, err := ioutil.TempDir("", "example")
	if err != nil {
		log.Fatal(err)
	}
	c, err := New(config.Options{
		CacheStorePath: dir + "/bolt.db", CacheStore: "bolt",
		SharedKey: cryptutil.NewBase64Key(),
		CacheURL:  &url.URL{Scheme: "http", Host: "example"}})
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	defer c.Close()
	tests := []struct {
		name       string
		ctx        context.Context
		SetRequest *cache.SetRequest
		SetReply   *cache.SetReply

		GetRequest   *cache.GetRequest
		GetReply     *cache.GetReply
		wantSetError bool
		wantGetError bool
	}{
		{"good",
			context.TODO(),
			&cache.SetRequest{Key: "key", Value: []byte("hello")},
			&cache.SetReply{},
			&cache.GetRequest{Key: "key"},
			&cache.GetReply{
				Exists: true,
				Value:  []byte("hello"),
			},
			false,
			false,
		},
		{"miss",
			context.TODO(),
			&cache.SetRequest{Key: "key", Value: []byte("hello")},
			&cache.SetReply{},
			&cache.GetRequest{Key: "no-such-key"},
			&cache.GetReply{
				Exists: false,
				Value:  nil,
			},
			false,
			false,
		},
		{"key too large",
			context.TODO(),
			&cache.SetRequest{Key: hugeKey, Value: []byte("hello")},
			nil,
			&cache.GetRequest{Key: hugeKey},
			&cache.GetReply{
				Exists: false,
				Value:  nil,
			},
			true,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			setGot, err := c.Set(tt.ctx, tt.SetRequest)
			if (err != nil) != tt.wantSetError {
				t.Errorf("Cache.Set() error = %v, wantSetError %v", err, tt.wantSetError)
				return
			}
			cmpOpts := []cmp.Option{
				cmpopts.IgnoreUnexported(cache.SetReply{}, cache.GetReply{}),
			}

			if diff := cmp.Diff(setGot, tt.SetReply, cmpOpts...); diff != "" {
				t.Errorf("Cache.Set() = %v", diff)
			}
			getGot, err := c.Get(tt.ctx, tt.GetRequest)
			if (err != nil) != tt.wantGetError {
				t.Errorf("Cache.Get() error = %v, wantGetError %v", err, tt.wantGetError)
				return
			}
			if diff := cmp.Diff(getGot, tt.GetReply, cmpOpts...); diff != "" {
				t.Errorf("Cache.Get() = %v", diff)
			}
		})
	}
}
