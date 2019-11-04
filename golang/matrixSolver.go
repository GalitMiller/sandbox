package main

import (
	"errors"
	"fmt"
)

type matrix [3][6]bool

func main() {
	fmt.Println("Hello, playground")
	TestSolve()

}

// O(n x m)
func solve(m *matrix) (ret int, err error) {
	if m == nil {
		return -1, errors.New("expecting 3 x 6 matrix")
	}
	for m.removeNext() {
	}
	return m.eval(), nil
}

// O(log(n x m))
func (m *matrix) removeNext() bool {
	smallest := struct{ v, r, c int }{}
	for r := range m {
		for c := range m[r] {
			if !m[r][c] {
				continue
			}
			v := m.val(r, c)
			if v == 1 {
				m[r][c] = false
				return true
			}
			if v <= smallest.v {
				continue
			}
			smallest.v = v
			smallest.c = c
			smallest.r = r
		}
	}
	if smallest.v > 0 {
		m[smallest.r][smallest.c] = false
		return true
	}
	return false
}

// O(n x m)
func (m *matrix) eval() (ret int) {
	for r := range m {
		for c := range m[r] {
			if m[r][c] {
				ret++
			}
		}
	}
	return ret
}

// O(n + m)
func (m matrix) val(row, col int) (ret int) {
	for i, r := range m {
		if i == row {
			for j := range r {
				if j != col && m[i][j] {
					ret++
				}
			}

		} else if r[col] {
			ret++
		}
	}
	return ret
}

func TestSolve() {
	type stest struct {
		input    *matrix
		expected int
	}
	tests := []stest{
		{
			input: &matrix{
				[6]bool{true, false, true, false, false, true},
				[6]bool{false, false, false, false, false, true},
				[6]bool{false, false, false, false, true, false},
			},
			expected: 2,
		},
		{
			input: &matrix{
				[6]bool{true, false, true, false, false, true},
				[6]bool{false, false, false, false, false, true},
				[6]bool{false, false, true, false, true, false},
			},
			expected: 1,
		},
		{
			input: &matrix{
				[6]bool{true, false, true, false, false, false},
				[6]bool{false, true, false, false, false, true},
				[6]bool{false, false, false, true, true, false},
			},
			expected: 3,
		},
	}
	for i, t := range tests {
		actual, err := solve(t.input)
		if err != nil {
			fmt.Printf("test %d: cannot solve this matrix, %s\n", i, err)
		}
		if actual != t.expected {
			fmt.Printf("test %d: expected %d, actual %d\n", i, t.expected, actual)
		} else {
			fmt.Printf("test %d: passed, %d\n", i, actual)
		}
	}
}
