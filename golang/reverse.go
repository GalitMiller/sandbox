package main

import (
	"fmt"
)

func main() {
	type test struct {
		input    string
		expected string
	}
	tests := []test{
		{input: "", expected: ""},
		{input: "a", expected: "a"},
		{input: "ab", expected: "ba"},
		{input: "abc", expected: "cba"},
		{input: "abcd", expected: "dcba"},
		{input: "abcde", expected: "edcba"},
		{input: "abcdef", expected: "fedcba"},
		{input: "aaaa", expected: "aaaa"},
	}
	for i, t := range tests {
		actual := reverse(t.input)
		if actual != t.expected {
			fmt.Printf("test %d: expected %s, actual %s\n", i, t.expected, actual)
		}
	}
}

func reverse(s string) string {
	if len(s) < 2 {
		return s
	}
	if len(s) > 2 {
		mid := len(s) / 2
		return reverse(s[mid:]) + reverse(s[:mid])
	}
	return string(s[1:] + s[:1])
}
