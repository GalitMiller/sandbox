package main

import (
	"fmt"
	"sort"
)

type test struct {
	input    []int
	expected []int
}
type sorter func(slist) []int

func main() {

	tests := []test{
		{input: []int{}, expected: []int{}},
		{input: []int{1}, expected: []int{1}},
		{input: []int{1, 1}, expected: []int{1}},
		{input: []int{1, 1, 2}, expected: []int{1, 2}},
		{input: []int{2, 1, 1}, expected: []int{2, 1}},
		{input: []int{1, 2, 1}, expected: []int{1, 2}},
		{input: []int{1, 2, 2, 1}, expected: []int{1, 2}},
		{input: []int{1, 2, 3, 2, 3, 3}, expected: []int{1, 2, 3}},
		{input: []int{1, 2, 3, 1, 2}, expected: []int{1, 2, 3}},
		{input: []int{1, 2, 3}, expected: []int{1, 2, 3}},
	}
	testRunner(dedup1, tests)
	testRunner(dedup2, tests)
}

func testRunner(fn sorter, tests []test) {
	for i, t := range tests {
		actual := dedup1(t.input)
		if len(t.expected) != len(actual) {
			fmt.Printf("test %d: expected len %d, actual %d\n", i, len(t.expected), len(actual))
		} else {
			for j, ev := range t.expected {
				if ev != actual[j] {
					fmt.Printf("test %d: expected[%d]=%d, actual %d", i, j, ev, actual[j])
				}
			}
		}
	}
}

// using map O(n)
func dedup1(in slist) (out []int) {
	m := make(map[int]bool)
	for _, v := range in {
		if _, ok := m[v]; !ok {
			out = append(out, v)
			m[v] = true
		}
	}
	return
}

// using sort O(nlog(n)) (in place)
type slist []int

func (l slist) Len() int           { return len(l) }
func (l slist) Swap(a, b int)      { (l)[a], (l)[b] = (l)[b], (l)[a] }
func (l slist) Less(a, b int) bool { return (l)[a] > (l)[b] }

func dedup2(in slist) (out []int) {
	sort.Sort(in)
	var prev int
	for i, v := range in {
		if i == 0 || v != prev {
			out = append(out, v)
			prev = v
		}
	}
	return
}
