package envoyconfig

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	lua "github.com/yuin/gopher-lua"
)

func TestLuaCleanUpstream(t *testing.T) {
	t.Parallel()

	L := newLua(t)

	bs, err := luaFS.ReadFile("luascripts/clean-upstream.lua")
	require.NoError(t, err)

	err = L.DoString(string(bs))
	require.NoError(t, err)

	headers := map[string]string{
		"context-type":             "text/plain",
		"authorization":            "Pomerium JWT",
		"x-pomerium-authorization": "JWT",
		"cookie":                   "cookieA=aaa_pomerium=123; cookieb=bbb; _pomerium=ey;_pomerium_test1=stillhere ; _pomerium_test2=stillhere",
	}
	metadata := map[string]any{
		"remove_pomerium_authorization": true,
		"remove_pomerium_cookie":        "_pomerium",
	}
	dynamicMetadata := map[string]map[string]any{}
	handle := newLuaResponseHandle(L, headers, metadata, dynamicMetadata)

	err = L.CallByParam(lua.P{
		Fn:      L.GetGlobal("envoy_on_request"),
		NRet:    0,
		Protect: true,
	}, handle)
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		"context-type": "text/plain",
		"cookie":       "cookieA=aaa_pomerium=123; cookieb=bbb; _pomerium_test1=stillhere ; _pomerium_test2=stillhere",
	}, headers)
}

func TestLuaLocalReplyContentType(t *testing.T) {
	t.Parallel()

	L := newLua(t)

	bs, err := luaFS.ReadFile("luascripts/local-reply-type.lua")
	require.NoError(t, err)

	err = L.DoString(string(bs))
	require.NoError(t, err)

	for _, tc := range []struct {
		contentType string
		accept      string
		expect      string
	}{
		{"", "text/html", "html"},
		{"", "application/json", "json"},
		{"", "text/plain", "plain"},
		{"", "text/plain,text/html", "plain"},
		{"", "text/plain;q=0.8,text/html;q=0.9", "html"},
		{"", "application/json;q=0.8,text/*;q=0.9", "html"},
		{"application/grpc", "", "grpc"},
	} {
		headers := map[string]string{
			"accept":       tc.accept,
			"content-type": tc.contentType,
		}
		dynamicMetadata := map[string]map[string]any{}
		handle := newLuaRequestHandle(L, headers, dynamicMetadata)

		err = L.CallByParam(lua.P{
			Fn:      L.GetGlobal("envoy_on_request"),
			NRet:    0,
			Protect: true,
		}, handle)
		require.NoError(t, err)
		assert.Equal(t, map[string]map[string]any{
			"envoy.filters.http.lua": {
				"pomerium_local_reply_type": tc.expect,
			},
		}, dynamicMetadata)
	}
}

func TestLuaRewriteHeaders(t *testing.T) {
	t.Parallel()

	L := newLua(t)

	bs, err := luaFS.ReadFile("luascripts/rewrite-headers.lua")
	require.NoError(t, err)

	err = L.DoString(string(bs))
	require.NoError(t, err)

	headers := map[string]string{
		"Location": "https://domain-with-dashes:8080/two/some/uri/",
	}
	metadata := map[string]any{
		"rewrite_response_headers": []any{
			map[string]any{
				"header": "Location",
				"prefix": "https://domain-with-dashes:8080/two/",
				"value":  "https://frontend/one/",
			},
			map[string]any{
				"header": "SomeOtherHeader",
				"prefix": "x",
				"value":  "y",
			},
		},
	}
	handle := newLuaResponseHandle(L, headers, metadata, nil)

	err = L.CallByParam(lua.P{
		Fn:      L.GetGlobal("envoy_on_response"),
		NRet:    0,
		Protect: true,
	}, handle)
	require.NoError(t, err)

	assert.Equal(t, "https://frontend/one/some/uri/", headers["Location"])
}

func newLua(t *testing.T) *lua.LState {
	L := lua.NewState()
	t.Cleanup(L.Close)

	L.SetGlobal("print", L.NewFunction(func(L *lua.LState) int {
		var args []any
		top := L.GetTop()
		for i := 1; i <= top; i++ {
			args = append(args, fromLua(L, L.Get(i)))
		}
		t.Log(args...)
		return 0
	}))

	return L
}

func newLuaRequestHandle(L *lua.LState,
	headers map[string]string,
	dynamicMetadata map[string]map[string]any,
) lua.LValue {
	return newLuaType(L, map[string]lua.LGFunction{
		"headers": func(L *lua.LState) int {
			L.Push(newLuaHeaders(L, headers))
			return 1
		},
		"streamInfo": func(L *lua.LState) int {
			L.Push(newLuaStreamInfo(L, dynamicMetadata))
			return 1
		},
	})
}

func newLuaResponseHandle(L *lua.LState,
	headers map[string]string,
	metadata map[string]any,
	dynamicMetadata map[string]map[string]any,
) lua.LValue {
	return newLuaType(L, map[string]lua.LGFunction{
		"headers": func(L *lua.LState) int {
			L.Push(newLuaHeaders(L, headers))
			return 1
		},
		"metadata": func(L *lua.LState) int {
			L.Push(newLuaMetadata(L, metadata))
			return 1
		},
		"streamInfo": func(L *lua.LState) int {
			L.Push(newLuaStreamInfo(L, dynamicMetadata))
			return 1
		},
	})
}

func newLuaHeaders(L *lua.LState, headers map[string]string) lua.LValue {
	typ := L.NewTable()
	L.SetFuncs(typ, map[string]lua.LGFunction{
		"get": func(L *lua.LState) int {
			_ = L.CheckTable(1)
			key := L.CheckString(2)

			str, ok := headers[key]
			if !ok {
				L.Push(lua.LNil)
				return 0
			}

			L.Push(lua.LString(str))
			return 1
		},
		"remove": func(L *lua.LState) int {
			_ = L.CheckTable(1)
			key := L.CheckString(2)
			delete(headers, key)
			return 0
		},
		"replace": func(L *lua.LState) int {
			_ = L.CheckTable(1)
			key := L.CheckString(2)
			value := L.CheckString(3)

			headers[key] = value

			return 0
		},
	})
	L.SetField(typ, "__index", typ)

	tbl := L.NewTable()
	L.SetMetatable(tbl, typ)
	return tbl
}

func newLuaMetadata(L *lua.LState, metadata map[string]any) lua.LValue {
	return newLuaType(L, map[string]lua.LGFunction{
		"get": func(L *lua.LState) int {
			_ = L.CheckTable(1)
			key := L.CheckString(2)

			obj, ok := metadata[key]
			if !ok {
				L.Push(lua.LNil)
				return 0
			}

			L.Push(toLua(L, obj))
			return 1
		},
	})
}

func newLuaDynamicMetadata(L *lua.LState, metadata map[string]map[string]any) lua.LValue {
	return newLuaType(L, map[string]lua.LGFunction{
		"get": func(L *lua.LState) int {
			_ = L.CheckTable(1)
			key := L.CheckString(2)

			obj, ok := metadata[key]
			if !ok {
				L.Push(lua.LNil)
				return 0
			}

			L.Push(toLua(L, obj))
			return 1
		},
		"set": func(L *lua.LState) int {
			_ = L.CheckTable(1)
			filterName := L.CheckString(2)
			key := L.CheckString(3)
			value := L.CheckAny(4)

			m, ok := metadata[filterName]
			if !ok {
				m = make(map[string]any)
				metadata[filterName] = m
			}
			m[key] = fromLua(L, value)

			return 0
		},
	})
}

func newLuaStreamInfo(L *lua.LState, dynamicMetadata map[string]map[string]any) lua.LValue {
	return newLuaType(L, map[string]lua.LGFunction{
		"dynamicMetadata": func(L *lua.LState) int {
			L.Push(newLuaDynamicMetadata(L, dynamicMetadata))
			return 1
		},
	})
}

func newLuaType(L *lua.LState, funcs map[string]lua.LGFunction) lua.LValue {
	typ := L.NewTable()
	L.SetFuncs(typ, funcs)
	L.SetField(typ, "__index", typ)

	tbl := L.NewTable()
	L.SetMetatable(tbl, typ)
	return tbl
}

func fromLua(L *lua.LState, v lua.LValue) any {
	switch v.Type() {
	case lua.LTNil:
		return nil
	case lua.LTBool:
		return bool(v.(lua.LBool))
	case lua.LTNumber:
		return float64(v.(lua.LNumber))
	case lua.LTString:
		return string(v.(lua.LString))
	case lua.LTTable:
		a := []any{}
		m := map[string]any{}
		v.(*lua.LTable).ForEach(func(key, value lua.LValue) {
			if key.Type() == lua.LTNumber {
				a = append(a, fromLua(L, value))
			} else {
				m[lua.LVAsString(key)] = fromLua(L, value)
			}
		})
		if len(a) > 0 {
			return a
		}
		return m
	default:
		panic("not supported")
	}
}

func toLua(L *lua.LState, obj any) lua.LValue {
	// send the object through JSON to remove custom types
	var normalized any
	bs, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(bs, &normalized)
	if err != nil {
		panic(err)
	}

	if normalized == nil {
		return lua.LNil
	}

	switch t := normalized.(type) {
	case []any:
		tbl := L.NewTable()
		for _, v := range t {
			tbl.Append(toLua(L, v))
		}
		return tbl
	case map[string]any:
		tbl := L.NewTable()
		for k, v := range t {
			L.SetField(tbl, k, toLua(L, v))
		}
		return tbl
	case bool:
		return lua.LBool(t)
	case float64:
		return lua.LNumber(t)
	case string:
		return lua.LString(t)
	default:
		panic(fmt.Sprintf("%T not supported for toLua", obj))
	}
}
