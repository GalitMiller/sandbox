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
    if ( _list.empty()  || !_list.front() || _list.front()->size() >= _max  )
    {
        my_list<T>* new_list = new my_list<T>;
        _list.push_front(new_list);
    }
    
    my_list<T> *current_list = _list.front();
    current_list->push_front(new_item);
}

template <class T>
T stack<T>::pop()
{
    if ( _list.empty() || !_list.front() || _list.front()->empty() )
        return NULL;
    
    my_list<T> *current_list = _list.front();
    T return_data = current_list->pop_front();
    
    if ( current_list->empty() )
    {
        _list.pop_front();
        delete current_list;
    }
    
    return return_data;
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
int stack<T>::numberOfSubstacks()
{
    return _list.size();
}

