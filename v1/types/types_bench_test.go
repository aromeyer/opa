// Copyright 2021 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package types

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
)

func BenchmarkSelect(b *testing.B) {
	sizes := []int{1000, 10000, 100000}
	for _, size := range sizes {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			tpe := generateType(size)
			runSelectBenchmark(b, tpe, json.Number(strconv.Itoa(size-1)))
		})
	}
}

func runSelectBenchmark(b *testing.B, tpe Type, key any) {
	b.ResetTimer()
	for range b.N {
		if result := Select(tpe, key); result != nil {
			if Compare(result, N) != 0 {
				b.Fatal("expected number type")
			}
		}
	}
}

func generateType(n int) Type {
	static := make([]*StaticProperty, n)
	for i := range n {
		static[i] = NewStaticProperty(json.Number(strconv.Itoa(i)), N)
	}
	return NewObject(static, nil)
}

func generateTypeWithPrefix(n int, prefix string) Type {
	static := make([]*StaticProperty, n)
	for i := range n {
		static[i] = NewStaticProperty(prefix+strconv.Itoa(i), S)
	}
	return NewObject(static, nil)
}

func BenchmarkAnyMergeOne(b *testing.B) {
	sizes := []int{100, 500, 1000, 5000, 10000}
	for _, size := range sizes {
		anyA := Any(make([]Type, 0, size))
		for i := range size {
			tpe := generateType(i)
			anyA = append(anyA, tpe)
		}
		tpeB := N
		b.ResetTimer()
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			result := anyA.Merge(tpeB)
			if len(result) != len(anyA)+1 {
				b.Fatalf("Expected length of merged result to be: %d, got: %d", len(anyA)+1, len(result))
			}
		})
	}
}

// Build up 2x Any type lists of unique and different types, then Union merge.
func BenchmarkAnyUnionAllUniqueTypes(b *testing.B) {
	sizes := []int{100, 250, 500, 1000, 2500}
	for _, sizeA := range sizes {
		for _, sizeB := range sizes {
			anyA := Any(make([]Type, 0, sizeA))
			for i := range sizeA {
				tpe := generateType(i)
				anyA = append(anyA, tpe)
			}
			anyB := Any(make([]Type, 0, sizeB))
			for i := range sizeB {
				tpe := generateTypeWithPrefix(i, "B-")
				anyB = append(anyB, tpe)
			}
			b.ResetTimer()
			b.Run(fmt.Sprintf("%dx%d", sizeA, sizeB), func(b *testing.B) {
				resultA2B := anyA.Union(anyB)
				// Expect length to be A + B - 1, because the `object` type is present in both Any type sets.
				if len(resultA2B) != (len(anyA) + len(anyB) - 1) {
					b.Fatalf("Expected length of unioned result to be: %d, got: %d", len(anyA)+len(anyB), len(resultA2B))
				}
			})
		}
	}
}
