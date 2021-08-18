package main

import (
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-12 lruBug bpf/lru_bug.c -- -Iinclude -Os

func main() {
	var objects lruBugObjects
	err := loadLruBugObjects(&objects, nil)
	if err != nil {
		panic(err)
	}
	defer func() {
		err = objects.Close()
		if err != nil {
			panic(err)
		}
	}()
	
	lruMap := objects.LruMap

	var value uint8

	n := 11
	for i := 0; i < n; i++ {
		fmt.Println("Add key =", i)
		err := lruMap.Update(uint16(i), uint8(1), ebpf.UpdateAny)
		if err != nil {
			panic(err)
		}
		time.Sleep(time.Second * 1)
	}
	for i := 0; i < n; i++ {
		err := lruMap.Lookup(uint16(i), &value)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			fmt.Println("Get key =", i, "= empty")
			continue
		} else if err != nil {
			panic(err)
		}
		fmt.Println("Get key =", i, "=", value)
	}
}
