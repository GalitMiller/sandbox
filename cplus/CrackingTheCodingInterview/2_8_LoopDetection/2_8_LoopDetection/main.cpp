//
//  main.cpp
//  2_8_LoopDetection
//
//  Created by Lesley Miller on 10/25/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>

template <class T>
struct node {
    T data;
    node* next;
};


template <class T>
void insertNew ( node<T> ** list, T data)
{
}


template <class T>
void insert ( node<T> ** list, node<T> *new_node )
{
    if ( *list )
        new_node->next = *list;
    *list = new_node;
}


template <class T>
void print ( node<T> *list )
{
    node<T> *current = list;
    
    while (current)
    {
        std::cout << current->data << "\n";
        current = current->next;
    }
}

template <class T>
node<T>* findLoop(node<T> *n)
{
    node<T>* runner = n;
    node<T>* follower = n;
    if (!runner || !runner->next || !runner->next->next)
        return NULL;
    
    return findLoop(n, runner->next->next, follower->next);
}

template <class T>
node<T>* findLoopPosition(node<T>* runner, node<T>* follower)
{
    while ( runner != follower && (runner && follower) )
    {
        runner = runner->next;
        follower = follower->next;
    }
    
    return runner;
}

template <class T>
node<T>* findLoop(node<T>* start, node<T>* runner, node<T>* follower)
{
    if ( !runner || !runner->next || !runner->next->next || !follower)
        return NULL;
    
    if ( runner == follower )
        return findLoopPosition(start, follower);
    
    return findLoop(start, runner->next->next, follower->next);
}

int main(int argc, const char * argv[]) {
    // insert code here...
    node<char> *a = NULL;
    
    node<char> *end_loop = new node<char>;
    end_loop->data = 't';
    insert (&a, end_loop);
    
    node<char> *n = new node<char>;
    n->data = 'i';
    insert (&a, n);
    
    n = new node<char>;
    n->data = 'l';
    insert (&a, n);
    
    n = new node<char>;
    n->data = 'a';
    insert (&a, n);
    
    node<char> *start_loop = new node<char>;
    start_loop->data = 'g';
    insert (&a, start_loop);
    
    n = new node<char>;
    n->data = 'i';
    insert (&a, n);
    
    n = new node<char>;
    n->data = 'h';
    insert (&a, n);
    
    end_loop->next = start_loop;
    
    
    
    std::cout << "I won't print my list because it might have a loop. Does it?: ";
    node<char> *loop = findLoop(n);
    loop ? std::cout << "yes. at '" << loop->data << "'\n" : std::cout << "nope.\n";

    
    return 0;
}
