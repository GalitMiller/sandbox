package main

import (
	"fmt"
)

func main() {
	TestStack()
}

func TestStack() {
	tests := []struct {
		list      []interface{}
		popLength int
		popValue  interface{}
	}{
		{[]interface{}{}, 0, nil},
		{[]interface{}{1}, 0, 1},
		{[]interface{}{1, 2}, 1, 2},
		{[]interface{}{1, 2, 3}, 2, 3},
	}
	for i, expct := range tests {
		stack := &Stack{}
		for j, d := range expct.list {
			length := stack.Push(d)
			if (j + 1) != length {
				fmt.Printf("TestStack %d: after push expected length %d, actual %d\n", i, j+1, length)
			}
		}

		pd := stack.Pop()
		if pd != expct.popValue {
			fmt.Printf("TestStack %d: expected pop data %d, actual %d\n", i, expct.popValue, pd)
		}

		l := stack.Length()
		if l != expct.popLength {
			fmt.Printf("TestStack %d: after pop expected length %d, actual %d\n", i, expct.popLength, l)
		}

	}
}

// stack
type Stack struct {
	Data []interface{}
}

// O(1)
func (l *Stack) Push(data interface{}) int {
	l.Data = append(l.Data, data)
	return len(l.Data)
}

// O(1)
func (l *Stack) Pop() (ret interface{}) {
	ln := len(l.Data)
	if ln == 0 {
		return
	}
	ret = l.Data[ln-1]
	l.Data = l.Data[:ln-1]
	return ret
}

// O(1)
func (l *Stack) Peak() (ret interface{}) {
	ln := len(l.Data)
	if ln != 0 {
		ret = l.Data[ln-1]
	}
	return
}

// O(1)
func (l *Stack) Length() int {
	return len(l.Data)
}
