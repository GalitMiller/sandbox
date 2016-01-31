//
//  my_list.h
//  3_0_ListStackAndQueue
//
//  Created by Lesley Miller on 10/25/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#ifndef ____0_ListStackAndQueue__list__
#define ____0_ListStackAndQueue__list__

#include <stdio.h>

template <class T>
struct node
{
    node* _next;
    T _data;
};

template <class T>
class my_list
{
public:
    my_list(){_front = NULL; _back = NULL; _size = 0;};
    
    void push_front(T data);
    void push_back(T data);
    T pop_front();
    T pop_back();
    T front();
    T back();
    T item_at(int index);
    bool empty();
    int size();

    
private:
    node<T>* _front;
    node<T>* _back;
    
    int _size;
};

#include "my_list.cpp"

#endif /* defined(____0_ListStackAndQueue__list__) */
