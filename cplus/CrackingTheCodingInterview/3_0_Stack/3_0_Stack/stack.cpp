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



