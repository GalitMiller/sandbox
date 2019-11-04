package main

import (
	"fmt"
)

type test struct {
	input    string
	expected bool
}

func main() {
	TestCheckParens()
}

func TestCheckParens() {
	tests := []test{
		{"", true},
		{")(", false},
		{"(", false},
		{")", false},
		{" )", false},
		{"()()", true},
		{"(())", true},
		{"))((", false},
		{"(()()", false},
		{"dsd(ddd)(dd)dddd", true},
		{"dsd(ddd)(dd)dddd)", false},
		{"(dsd(ddd)(dd)dddd", false},
		{")dsd(ddd)(dd)dddd", false},
	}
	for i, dt := range tests {
		actual := checkParens(dt.input)
		if actual != dt.expected {
			fmt.Printf("test %s: expected %v, actual %v\n", dt.input, dt.expected, actual)
		}
	}
}

func checkParens(s string) bool {
	var stack int
	for _, v := range s {
		if v == '(' {
			stack++
		} else if v == ')' {
			if stack < 1 {
				return false
			}
			stack--
		}
	}

	return stack == 0
}
