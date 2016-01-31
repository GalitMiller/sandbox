//
//  my_list.cpp
//  3_0_ListStackAndQueue
//
//  Created by Lesley Miller on 10/25/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include "my_list.h"

template <class T>

void my_list<T>::my_list<T>()
{
    _front = NULL;
    _back = NULL;
    _size = 0;
}

void my_list<T>::push_front(T data)
{
    node<T> *new_node = new node;
    new_node->data = data;
    new_node->next = _front;
    
    _front = new_node;
    
    if ( !_back )
        _back = new_node;
    
    _size++;
}

template <class T>
void my_list<T>::push_back(T data)
{
    node<T> *new_node = new node;
    new_node->data = data;
    new_node->next = NULL;
    
    if ( !_front )
        _front = new_node;
    
    if ( _back )
        _back->next = new_node;
    
    _back = new_node;
    
    
    _size++;
}

template <class T>
T my_list<T>::pop_front()
{
    if ( !_front )
        return NULL;
    
    T old_front_data = _front->data;
    node* old_front = _front;
    
    _front = _front->next;
    delete old_front;
    
    _size--;
    return old_front_data;
}

template <class T>
T my_list<T>::pop_back()
{
    if ( !_back )
        return NULL;
    
    node<T> *new_back = _front;
    T old_back = _back->data;
    
    while ( true )
    {
        if ( new_back->next == _back )
            break;
        new_back = new_back->next;
    }
    

    delete _back;
    _back = new_back;
    
    size --;
    
    return old_back;
    
}

template <class T>
T my_list<T>::front()
{
    if ( _front )
        return _front->data;
    else
        return NULL;
}

template <class T>
T my_list<T>::back()
{
    if ( _back )
        return _back->data;
    else
        return NULL;
}

template <class T>
bool my_list<T>::empty()
{
    return _size > 0 ? false : true;
    
}

template <class T>
int my_list<T>::size()
{
    return _size;
}