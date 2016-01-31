//
//  queue.cpp
//  3_0_StackAndQueue
//
//  Created by Lesley Miller on 10/25/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include "queue.h"

template <class T>
void queue<T>::add(T new_item)
{
    _list.push_front(new_item);
}

template <class T>
T queue<T>::remove()
{
    T last_item = _list.back();
    _list.pop_back();
    return last_item;
}

template <class T>
T queue<T>::peak()
{
    return _list.back();
}

template <class T>
bool queue<T>::isEmpty()
{
    return _list.size() > 0 ? false : true;
}