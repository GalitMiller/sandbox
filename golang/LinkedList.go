package main

import (
	"fmt"
)

func main() {
	TestAppend()
	TestStart()
	TestEnd()
	TestRemovePos()
	TestRemoveVal()
	TestInsert()
	TestGet()
}

func TestAppend() {
	list := &LList{}

	tests := []struct {
		data   interface{}
		length uint
	}{{"1", 1}, {"", 2}, {"a", 3}, {"asdf", 4}}
	if list.Length != 0 {
		fmt.Printf("expected length %d, actual %d\n", 0, list.Length)
	}
	for i, expct := range tests {
		if list.Append(expct.data).Length != expct.length {
			fmt.Printf("TestAppend %d: expected length %d, actual %d\n", i, expct.length, list.Length)
		}
	}
}

func TestStart() {
	list := &LList{}

	tests := []struct {
		data  interface{}
		start interface{}
	}{{"1", "1"}, {"", "1"}, {"a", "1"}, {"asdf", "1"}}
	for i, expct := range tests {
		if list.Append(expct.data).First.Data != expct.start {
			fmt.Printf("TestStart %d: expected start %v, actual %v\n", i, expct.start, list.First.Data)
		}
	}
}

func TestEnd() {
	list := &LList{}

	tests := []struct {
		data interface{}
		end  interface{}
	}{{"1", "1"}, {"", ""}, {"a", "a"}, {nil, nil}, {"asdf", "asdf"}}
	for i, expct := range tests {
		if list.Append(expct.data).Last.Data != expct.end {
			fmt.Printf("TestEnd %d: expected end %v, actual %v\n", i, expct.end, list.Last.Data)
		}
	}
}

func TestRemovePos() {
	list := &LList{}

	tests := []struct {
		list   []interface{}
		pos    uint
		length uint
		start  interface{}
		end    interface{}
	}{
		{[]interface{}{}, 0, 0, nil, nil},
		{[]interface{}{}, 1, 0, nil, nil},
		{[]interface{}{1}, 0, 0, nil, nil},
		{[]interface{}{1}, 1, 1, 1, 1},
		{[]interface{}{1}, 2, 1, 1, 1},
		{[]interface{}{1, 2}, 0, 1, 2, 2},
		{[]interface{}{1, 2}, 1, 1, 1, 1},
		{[]interface{}{1, 2}, 2, 2, 1, 2},
		{[]interface{}{1, 2}, 3, 2, 1, 2},
		{[]interface{}{1, 2, 3}, 0, 2, 2, 3},
		{[]interface{}{1, 2, 3}, 1, 2, 1, 3},
		{[]interface{}{1, 2, 3}, 2, 2, 1, 2},
		{[]interface{}{1, 2, 3}, 3, 3, 1, 3},
		{[]interface{}{1, 2, 3}, 4, 3, 1, 3},
	}
	for i, expct := range tests {
		list = &LList{}
		for _, d := range expct.list {
			list.Append(d)
		}
		if list.RemovePos(expct.pos).Length != expct.length {
			fmt.Printf("TestRemovePos %d: expected length %d, actual %d\n", i, expct.length, list.Length)
		}
		if expct.start == nil {
			if list.First != nil {
				fmt.Printf("TestRemovePos %d: expected start nil, actual %v\n", i, list.First.Data)
			}
		} else if list.First.Data != expct.start {
			fmt.Printf("TestRemovePos %d: expected start %v, actual %v\n", i, expct.start, list.First.Data)
		}
		if expct.end == nil {
			if list.Last != nil {
				fmt.Printf("TestRemovePos %d: expected end nil, actual %v\n", i, list.Last.Data)
			}
		} else if list.Last.Data != expct.end {
			fmt.Printf("TestRemovePos %d: expected end %v, actual %v\n", i, expct.end, list.Last.Data)
		}
	}
}

func TestRemoveVal() {
	list := &LList{}

	tests := []struct {
		list   []interface{}
		val    interface{}
		length uint
		start  interface{}
		end    interface{}
	}{
		{[]interface{}{}, 0, 0, nil, nil},
		{[]interface{}{}, 1, 0, nil, nil},
		{[]interface{}{1}, 1, 0, nil, nil},
		{[]interface{}{1}, 0, 1, 1, 1},
		{[]interface{}{1, 2}, 0, 2, 1, 2},
		{[]interface{}{1, 2}, 1, 1, 2, 2},
		{[]interface{}{1, 2}, 2, 1, 1, 1},
		{[]interface{}{1, 2}, 3, 2, 1, 2},
		{[]interface{}{1, 2, 3}, 0, 3, 1, 3},
		{[]interface{}{1, 2, 3}, 1, 2, 2, 3},
		{[]interface{}{1, 2, 3}, 2, 2, 1, 3},
		{[]interface{}{1, 2, 3}, 2, 2, 1, 3},
		{[]interface{}{1, 2, 3}, 4, 3, 1, 3},
	}
	for i, expct := range tests {
		list = &LList{}
		for _, d := range expct.list {
			list.Append(d)
		}
		if list.RemoveVal(expct.val).Length != expct.length {
			fmt.Printf("TestRemoveVal %d: expected length %d, actual %d\n", i, expct.length, list.Length)
		}
		if expct.start == nil {
			if list.First != nil {
				fmt.Printf("TestRemoveVal %d: expected start nil, actual %v\n", i, list.First.Data)
			}
		} else if list.First.Data != expct.start {
			fmt.Printf("TestRemoveVal %d: expected start %v, actual %v\n", i, expct.start, list.First.Data)
		}
		if expct.end == nil {
			if list.Last != nil {
				fmt.Printf("TestRemoveVal %d: expected end nil, actual %v\n", i, list.Last.Data)
			}
		} else if list.Last.Data != expct.end {
			fmt.Printf("TestRemoveVal %d: expected end %v, actual %v\n", i, expct.end, list.Last.Data)
		}
	}
}

func TestInsert() {
	list := &LList{}

	tests := []struct {
		list   []interface{}
		pos    uint
		data   interface{}
		length uint
		start  interface{}
		end    interface{}
	}{
		{[]interface{}{}, 0, "new", 1, "new", "new"},
		{[]interface{}{}, 1, "new", 0, nil, nil},
		{[]interface{}{1}, 0, "new", 2, "new", 1},
		{[]interface{}{1}, 1, "new", 2, 1, "new"},
		{[]interface{}{1}, 2, "new", 1, 1, 1},
		{[]interface{}{1, 2}, 0, "new", 3, "new", 2},
		{[]interface{}{1, 2}, 1, "new", 3, 1, 2},
		{[]interface{}{1, 2}, 2, "new", 3, 1, "new"},
		{[]interface{}{1, 2}, 3, "new", 2, 1, 2},
		{[]interface{}{1, 2, 3}, 0, "new", 4, "new", 3},
		{[]interface{}{1, 2, 3}, 1, "new", 4, 1, 3},
		{[]interface{}{1, 2, 3}, 2, "new", 4, 1, 3},
		{[]interface{}{1, 2, 3}, 3, "new", 4, 1, "new"},
		{[]interface{}{1, 2, 3}, 4, "new", 3, 1, 3},
	}
	for i, expct := range tests {
		list = &LList{}
		for _, d := range expct.list {
			list.Append(d)
		}
		if list.Insert(expct.data, expct.pos).Length != expct.length {
			fmt.Printf("TestInsertPos %d: expected length %d, actual %d\n", i, expct.length, list.Length)
		}
		if expct.start == nil {
			if list.First != nil {
				fmt.Printf("TestInsertPos %d: expected start nil, actual %v\n", i, list.First.Data)
			}
		} else if list.First.Data != expct.start {
			fmt.Printf("TestInsertPos %d: expected start %v, actual %v\n", i, expct.start, list.First.Data)
		}
		if expct.end == nil {
			if list.Last != nil {
				fmt.Printf("TestInsertPos %d: expected end nil, actual %v\n", i, list.Last.Data)
			}
		} else if list.Last.Data != expct.end {
			fmt.Printf("TestInsertPos %d: expected end %v, actual %v\n", i, expct.end, list.Last.Data)
		}
	}
}

func TestGet() {
	list := &LList{}

	tests := []struct {
		list []interface{}
		pos  uint
		data interface{}
	}{
		{[]interface{}{}, 0, nil},
		{[]interface{}{}, 1, nil},
		{[]interface{}{1}, 0, 1},
		{[]interface{}{1}, 1, nil},
		{[]interface{}{1, 2}, 0, 1},
		{[]interface{}{1, 2}, 1, 2},
		{[]interface{}{1, 2}, 2, nil},
		{[]interface{}{1, 2, 3}, 0, 1},
		{[]interface{}{1, 2, 3}, 1, 2},
		{[]interface{}{1, 2, 3}, 2, 3},
		{[]interface{}{1, 2, 3}, 3, nil},
		{[]interface{}{1, 2, 3}, 4, nil},
	}
	for i, expct := range tests {
		list = &LList{}
		for _, d := range expct.list {
			list.Append(d)
		}
		actual := list.Get(expct.pos)
		if expct.data == nil {
			if actual != nil {
				fmt.Printf("TestGet %d: expected nil, actual %d\n", i, actual)
			}
		} else if actual.Data != expct.data {
			fmt.Printf("TestGet %d: expected %d, actual %d\n", i, expct.data, actual.Data)
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
