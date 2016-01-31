//
//  my_list.cpp
//  3_0_ListStackAndQueue
//
//  Created by Lesley Miller on 10/25/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include "my_list.h"


/*void my_list<T>::my_list()
{
    _front = NULL;
    _back = NULL;
    _size = 0;
}*/

template <class T>
void my_list<T>::push_front(T data)
{
    node<T> *new_node = new node<T>;
    new_node->_data = data;
    new_node->_next = _front;
    
    _front = new_node;
    
    if ( !_back )
        _back = new_node;
    
    _size++;
}

template <class T>
void my_list<T>::push_back(T data)
{
    node<T> *new_node = new node<T>;
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
    {
        T blank;
        return blank;
    }
    
    T old_front_data = _front->_data;
    node<T>* old_front = _front;
    
    _front = _front->_next;
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
    
    _size --;
    
    return old_back;
    
}

template <class T>
T my_list<T>::front()
{
    if ( _front )
        return _front->_data;
    else
    {
        T blank;
        return blank;
    }
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
T my_list<T>::item_at(int index)
{
    int counter = 0;
    node<T>* node_at_index = _front;
    while ( true )
    {
        if ( counter == index || !node_at_index )
            break;
        
        counter++;
        node_at_index = node_at_index->next;
    }
    
    return node_at_index ? node_at_index->_data : NULL;
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