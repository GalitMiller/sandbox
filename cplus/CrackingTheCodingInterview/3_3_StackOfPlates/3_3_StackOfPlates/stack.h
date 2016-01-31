//
//  stack.h
//  3_0_Stack
//
//  Created by Lesley Miller on 10/25/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#ifndef ____0_Stack__stack__
#define ____0_Stack__stack__

#include <stdio.h>
#include "my_list.h"

template <class T>
class stack
{
public:
    stack(int max) {_max = max;};
    
    void push(T new_item);
    T pop();
    T peak();
    bool isEmpty();
    int numberOfSubstacks();
    
private:
    my_list< my_list<T>* > _list;
    int _max;
    
};

#include "stack.cpp"

#endif /* defined(____0_Stack__stack__) */
