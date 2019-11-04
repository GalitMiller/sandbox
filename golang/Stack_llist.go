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
		popLength uint
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
			if uint(j+1) != length {
				fmt.Printf("TestStack %d: after push expected length %d, actual %d\n", i, j+1, length)
			}
		}

		pd := stack.Pop()
		if pd != expct.popValue {
			fmt.Printf("TestStack %d: expected pop data %d, actual %d\n", i, expct.popValue, pd)
		}

		l := stack.Length
		if l != expct.popLength {
			fmt.Printf("TestStack %d: after pop expected length %d, actual %d\n", i, expct.popLength, l)
		}

	}
}

type Node struct {
	Data interface{}
	Next *Node
}

type LList struct {
	First  *Node
	Last   *Node
	Length uint
}

// O(1)
func (l *LList) Append(data interface{}) *LList {
	n := &Node{Data: data}
	if l.Length == 0 {
		l.First = n
	} else {
		l.Last.Next = n
	}
	l.Last = n

	l.Length++
	return l
}

// O(n)
func (l *LList) Get(pos uint) *Node {
	if pos >= l.Length {
		return nil
	}

	var i uint
	c := l.First
	for c != nil && i < pos {
		c = c.Next
		i++
	}
	return c
}

// O(n)
func (l *LList) Insert(data interface{}, pos uint) *LList {
	if pos > l.Length {
		return l
	}

	var n, p, c *Node
	var i uint

	n = &Node{Data: data}
	c = l.First
	for c != nil && i < pos {
		p, c = c, c.Next
		i++
	}

	if p != nil {
		p.Next = n
	} else {
		l.First = n
	}
	if c != nil {
		n.Next = c
	} else {
		l.Last = n
	}

	l.Length++
	return l
}

// O(n)
func (l *LList) RemovePos(pos uint) *LList {
	if pos >= l.Length {
		return l
	}

	var p, c *Node
	if pos == 0 {
		p = l.First.Next
		l.First = l.First.Next
	} else {
		var i uint
		c = l.First
		for i < pos {
			p, c = c, c.Next
			i++
		}
		p.Next = c.Next
	}
	if pos == l.Length-1 {
		l.Last = p
	}

	l.Length--
	return l
}

// O(n)
func (l *LList) RemoveVal(data interface{}) *LList {
	if l.Length == 0 {
		return l
	}

	var p, c *Node
	c = l.First
	for c != nil {
		if c.Data == data {
			if p == nil {
				l.First = c.Next
			} else {
				p.Next = c.Next
			}
			if c.Next == nil {
				l.Last = p
			}
			l.Length--
			break
		}
		p, c = c, c.Next
	}

	return l
}

// stack
type Stack struct {
	LList
}

// O(1)
func (l *Stack) Push(data interface{}) uint {
	return l.Append(data).Length
}

// O(n)
func (l *Stack) Pop() interface{} {
	if l.Length == 0 {
		return nil
	}
	ret := l.Peak()
	l.RemovePos(l.Length - 1)
	return ret
}

// O(1)
func (l *Stack) Peak() interface{} {
	if l.Length == 0 {
		return nil
	}
	return l.Last.Data
}
