package envoyconfig

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	lua "github.com/yuin/gopher-lua"
)

func TestLuaFixMisdirected(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		L := lua.NewState()
		defer L.Close()

		bs, err := luaFS.ReadFile("luascripts/fix-misdirected.lua")
		require.NoError(t, err)

		err = L.DoString(string(bs))
		require.NoError(t, err)

		headers := map[string]string{
			":authority": "TEST",
		}
		metadata := map[string]interface{}{}
		dynamicMetadata := map[string]map[string]interface{}{}
		handle := newLuaResponseHandle(L, headers, metadata, dynamicMetadata)

		err = L.CallByParam(lua.P{
			Fn:      L.GetGlobal("envoy_on_request"),
			NRet:    0,
			Protect: true,
		}, handle)
		require.NoError(t, err)

		assert.Equal(t, map[string]map[string]interface{}{
			"envoy.filters.http.lua": {
				"request.authority": "TEST",
			},
		}, dynamicMetadata)
	})
	t.Run("empty metadata", func(t *testing.T) {
		L := lua.NewState()
		defer L.Close()

		bs, err := luaFS.ReadFile("luascripts/fix-misdirected.lua")
		require.NoError(t, err)

		err = L.DoString(string(bs))
		require.NoError(t, err)

		headers := map[string]string{}
		metadata := map[string]interface{}{}
		dynamicMetadata := map[string]map[string]interface{}{}
		handle := newLuaResponseHandle(L, headers, metadata, dynamicMetadata)

		err = L.CallByParam(lua.P{
			Fn:      L.GetGlobal("envoy_on_response"),
			NRet:    0,
			Protect: true,
		}, handle)
		require.NoError(t, err)
	})
}

func TestLuaRewriteHeaders(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	bs, err := luaFS.ReadFile("luascripts/rewrite-headers.lua")
	require.NoError(t, err)

	err = L.DoString(string(bs))
	require.NoError(t, err)

	headers := map[string]string{
		"Location": "https://localhost:8080/two/some/uri/",
	}
	metadata := map[string]interface{}{
		"rewrite_response_headers": []interface{}{
			map[string]interface{}{
				"header": "Location",
				"prefix": "https://localhost:8080/two/",
				"value":  "https://frontend/one/",
			},
			map[string]interface{}{
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

func newLuaResponseHandle(L *lua.LState,
	headers map[string]string,
	metadata map[string]interface{},
	dynamicMetadata map[string]map[string]interface{},
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

func newLuaMetadata(L *lua.LState, metadata map[string]interface{}) lua.LValue {
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

func newLuaDynamicMetadata(L *lua.LState, metadata map[string]map[string]interface{}) lua.LValue {
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
				m = make(map[string]interface{})
				metadata[filterName] = m
			}
			m[key] = fromLua(L, value)

			return 0
		},
	})
}

func newLuaStreamInfo(L *lua.LState, dynamicMetadata map[string]map[string]interface{}) lua.LValue {
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

func fromLua(L *lua.LState, v lua.LValue) interface{} {
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
		a := []interface{}{}
		m := map[string]interface{}{}
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

func toLua(L *lua.LState, obj interface{}) lua.LValue {
	// send the object through JSON to remove custom types
	var normalized interface{}
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
	case []interface{}:
		tbl := L.NewTable()
		for _, v := range t {
			tbl.Append(toLua(L, v))
		}
		return tbl
	case map[string]interface{}:
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
