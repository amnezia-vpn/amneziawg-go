package adapter

import (
	"encoding/base64"
	"fmt"
	"sync/atomic"

	"github.com/aarzilli/golua/lua"
)

type Lua struct {
	generateState *lua.State
	parseState    *lua.State
	packetCounter atomic.Int64
	base64LuaCode string
}

type LuaParams struct {
	Base64LuaCode string
}

func NewLua(params LuaParams) (*Lua, error) {
	luaCode, err := base64.StdEncoding.DecodeString(params.Base64LuaCode)
	if err != nil {
		return nil, err
	}

	strLuaCode := string(luaCode)
	// fmt.Println(strLuaCode)

	generateState, err := initState(strLuaCode)
	if err != nil {
		return nil, err
	}
	parseState, err := initState(strLuaCode)
	if err != nil {
		return nil, err
	}

	return &Lua{
		generateState: generateState,
		parseState:    parseState,
		base64LuaCode: params.Base64LuaCode,
	}, nil
}

func initState(luaCode string) (*lua.State, error) {
	state := lua.NewState()
	state.OpenLibs()

	if err := state.DoString(string(luaCode)); err != nil {
		return nil, fmt.Errorf("Error loading Lua code: %v\n", err)
	}
	return state, nil
}

func (l *Lua) Close() {
	l.generateState.Close()
	l.parseState.Close()
}

// Only thread safe if used by wg packet creation which happens independably
func (l *Lua) Generate(
	msgType int64,
	data []byte,
) ([]byte, error) {
	l.generateState.GetGlobal("d_gen")

	l.generateState.PushInteger(msgType)
	l.generateState.PushBytes(data)
	l.generateState.PushInteger(l.packetCounter.Add(1))

	if err := l.generateState.Call(3, 1); err != nil {
		return nil, fmt.Errorf("Error calling Lua function: %v\n", err)
	}

	result := l.generateState.ToBytes(-1)
	l.generateState.Pop(1)

	return result, nil
}

// Only thread safe if used by wg packet receive which happens independably
func (l *Lua) Parse(data []byte) ([]byte, error) {
	l.parseState.GetGlobal("d_parse")

	l.parseState.PushBytes(data)
	if err := l.parseState.Call(1, 1); err != nil {
		return nil, fmt.Errorf("Error calling Lua function: %v\n", err)
	}

	result := l.parseState.ToBytes(-1)
	l.parseState.Pop(1)

	return result, nil
}

func (l *Lua) Base64LuaCode() string {
	return l.base64LuaCode
}
