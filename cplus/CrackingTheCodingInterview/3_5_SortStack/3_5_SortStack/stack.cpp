//
//  stack.cpp
//  3_0_Stack
//
//  Created by Lesley Miller on 10/25/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include "stack.h"

template <class T>
void stack<T>::push(T new_item)
{
    _list.push_front(new_item);
}

template <class T>
T stack<T>::pop()
{
    T front = _list.front();
    _list.pop_front();
    return front;
}


template <class T>
T stack<T>::peak()
{
    return _list.front();
}

template <class T>
bool stack<T>::isEmpty()
{
    return _list.size() > 0 ? false : true;
}

template <class T>
void stack<T>::sort()
{
    
    stack<T> temp_stack;
    
    while (!isEmpty())
    {
        if ( temp_stack.isEmpty() || temp_stack.peak() <= peak() )
        {
            temp_stack.push(pop());
            continue;
        }
        T temp = pop();
        int count = 0;
        while ( !temp_stack.isEmpty() && temp_stack.peak() > temp )
        {
            push(temp_stack.pop());
            count++;
        }
        temp_stack.push(temp);
        for ( int i = 1; i <= count; i++ )
            temp_stack.push(pop());
    }
    
    while (!temp_stack.isEmpty())
    {
        push(temp_stack.pop());
    }
    
}