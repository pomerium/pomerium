package controlplane

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	lua "github.com/yuin/gopher-lua"
)

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
	handle := newLuaResponseHandle(L, headers, metadata)

	err = L.CallByParam(lua.P{
		Fn:      L.GetGlobal("envoy_on_response"),
		NRet:    0,
		Protect: true,
	}, handle)
	require.NoError(t, err)

	assert.Equal(t, "https://frontend/one/some/uri/", headers["Location"])
}

func newLuaResponseHandle(L *lua.LState, headers map[string]string, metadata map[string]interface{}) lua.LValue {
	typ := L.NewTable()
	L.SetFuncs(typ, map[string]lua.LGFunction{
		"headers": func(L *lua.LState) int {
			L.Push(newLuaHeaders(L, headers))
			return 1
		},
		"metadata": func(L *lua.LState) int {
			L.Push(newLuaMetadata(L, metadata))
			return 1
		},
	})
	L.SetField(typ, "__index", typ)

	tbl := L.NewTable()
	L.SetMetatable(tbl, typ)
	return tbl
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
	typ := L.NewTable()
	L.SetFuncs(typ, map[string]lua.LGFunction{
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
	L.SetField(typ, "__index", typ)

	tbl := L.NewTable()
	L.SetMetatable(tbl, typ)
	return tbl
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
