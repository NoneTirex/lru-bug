package main

import (
	"fmt"
	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf lruBug bpf/lru_bug.c -- -Iinclude -Os

type handle func(lruMap *ebpf.Map)

func test(fn handle) {
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
	fn(objects.LruMap)
}

func main() {
	test(func(lruMap *ebpf.Map) {
		fmt.Println("Key size:", lruMap.KeySize())
		fmt.Println("Value size:", lruMap.ValueSize())
		fmt.Println("Max entries:", lruMap.MaxEntries())
		fmt.Println("Flags:", lruMap.Flags())
		fmt.Println("Is pinned:", lruMap.IsPinned())
	})

	fmt.Println()
	fmt.Println("###")
	fmt.Println("First behaviour:")
	fmt.Println("###")
	fmt.Println()
	test(func(lruMap *ebpf.Map) {
		var key uint16
		var value uint8

		n := 10
		for i := 1; i <= n; i++ {
			fmt.Println("Add key =", i)
			k := uint16(i)
			v := uint8(1)
			err := lruMap.Update(k, v, ebpf.UpdateNoExist)
			if err != nil {
				fmt.Println(err)
				return
			}
			// as described here: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=3a08c2fd763450a927d1130de078d6f9e74944fb
			// The active list, as its name says it, maintains the active set of
			//   the nodes.  We can think of it as the working set or more frequently
			//   accessed nodes.  The access frequency is approximated by a ref-bit.
			//   The ref-bit is set during the bpf_lookup_elem()
			err = lruMap.Lookup(k, &value)
			if err != nil {
				fmt.Println(err)
				return
			}
		}
		fmt.Println("iterate")

		// this iterator will print every elements
		iterate := lruMap.Iterate()
		for iterate.Next(&key, &value) {
			fmt.Println("Get key =", key, "=", value)
		}

		if iterate.Err() != nil {
			fmt.Println("iterator error", iterate.Err())
		}
		// add n + 1
		err := lruMap.Update(uint16(n+1), uint8(1), ebpf.UpdateNoExist)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = lruMap.Lookup(uint16(n+1), &value)
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("iterate2")

		// this iterator will print only one element (n + 1)
		iterate = lruMap.Iterate()
		for iterate.Next(&key, &value) {
			fmt.Println("Get key =", key, "=", value)
		}

		if iterate.Err() != nil {
			fmt.Println("iterator error", iterate.Err())
		}
	})

	fmt.Println()
	fmt.Println("###")
	fmt.Println("Second behaviour:")
	fmt.Println("###")
	fmt.Println()
	test(func(lruMap *ebpf.Map) {
		var key uint16
		var value uint8

		n := 10
		for i := 1; i <= n; i++ {
			fmt.Println("Add key =", i)
			k := uint16(i)
			v := uint8(1)
			// every elements update is successful and iterator will print every added element
			err := lruMap.Update(k, v, ebpf.UpdateNoExist)
			if err != nil {
				fmt.Println(err)
				return
			}
		}
		fmt.Println("iterate")

		iterate := lruMap.Iterate()
		for iterate.Next(&key, &value) {
			fmt.Println("Get key =", key, "=", value)
		}

		if iterate.Err() != nil {
			fmt.Println("iterator error", iterate.Err())
		}
	})

	fmt.Println()
	fmt.Println("###")
	fmt.Println("Third behaviour:")
	fmt.Println("###")
	fmt.Println()
	test(func(lruMap *ebpf.Map) {
		var key uint16
		var value uint8

		n := 10
		for i := 1; i <= n; i++ {
			fmt.Println("Add key =", i)
			k := uint16(i)
			v := uint8(1)
			err := lruMap.Update(k, v, ebpf.UpdateNoExist)
			if err != nil {
				fmt.Println(err)
				return
			} else {
				// I dont know why, but the update of last element will return error (key does not exist) and iterator will be empty
				err = lruMap.Update(k, v, ebpf.UpdateExist)
				fmt.Println(err)
			}
		}
		fmt.Println("iterate")

		iterate := lruMap.Iterate()
		for iterate.Next(&key, &value) {
			fmt.Println("Get key =", key, "=", value)
		}

		if iterate.Err() != nil {
			fmt.Println("iterator error", iterate.Err())
		}
	})
}
