//
//  queue.h
//  3_0_StackAndQueue
//
//  Created by Lesley Miller on 10/25/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#ifndef ____0_StackAndQueue__queue__
#define ____0_StackAndQueue__queue__

#include <stdio.h>
#include "my_list.h"

template <class T>
class queue
{
public:
    void add(T new_item);
    T remove();
    T peak();
    bool isEmpty();
    
private:
    my_list<T> _list;
    
};

#include "queue.cpp"

#endif /* defined(____0_StackAndQueue__queue__) */
