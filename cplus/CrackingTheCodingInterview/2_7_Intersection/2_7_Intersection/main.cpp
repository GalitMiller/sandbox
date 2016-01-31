//
//  main.cpp
//  2_7_Intersection
//
//  Created by Lesley Miller on 10/24/15.
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
node<T>* getTail(node<T>* n, int &length)
{
    length++;
    if ( !n->next )
        return n;
    
    return getTail(n->next, length);
}

template <class T>
node<T>* getIntersection(node<T>* a, node<T> * b)
{
    if ( !a->next && !b->next )
        return (a == b ? a : NULL);
    
    //lists should be the same size.
    if ( !a->next )
        return getIntersection(a, b->next);
    
    if ( !b->next )
        return getIntersection(a->next, b);
    
    node<T> *i = getIntersection(a->next, b->next);
    
    if ( !i ) return NULL;
    
    //are the lists still intersected?
    if ( a == b )
        return a;
    
    //return the last intersection;
    return i;
}

template <class T>
node<T>* getIntersectingNode(node<T>* a, node<T>* b)
{
    int length_a = 0;
    int length_b = 0;
    node<T>* tail_a = getTail(a, length_a);
    node<T>* tail_b = getTail(b, length_b);
    
    if ( tail_a != tail_b )
        return NULL;
    
    while ( length_a > length_b )
    {
        a = a->next;
        length_a--;
    }
    
    while ( length_b > length_a )
    {
        b = b->next;
        length_b--;
    }
    
    return getIntersection(a, b);
}


int main(int argc, const char * argv[]) {

    node<char> *a = NULL;
    node<char> *b = NULL;
    
    node<char> node8;
    node8.data = 't';
    insert (&a, &node8);
    
    node<char> node7;
    node7.data = 'i';
    insert (&a, &node7);
    
    node<char> node6;
    node6.data = 'l';
    insert (&a, &node6);
    
    node<char> node5;
    node5.data = 'a';
    insert (&a, &node5);
    
    node<char> node4;
    node4.data = 'g';
    insert (&a, &node4);
    insert (&b, &node4);
    
    node<char> node22;
    node22.data = 'i';
    insert (&b, &node22);
    
    node<char> node11;
    node11.data = 'h';
    insert (&b, &node11);
    
    node<char> node3;
    node3.data = 'e';
    insert (&a, &node3);
    
    node<char> node2;
    node2.data = 'y';
    insert (&a, &node2);
    
    node<char> node1;
    node1.data = 'b';
    insert (&a, &node1);
    
    
    std::cout << "This is my first list:\n";
    print(a);
    
    std::cout << "\nThis is my second list:\n";
    print(b);
    
    
    std::cout << "\nDo they intersect?: ";
    node<char> *i = getIntersectingNode(a, b);
    
    if ( i )
        std::cout << "yes. at " << i->data << "\n";
    else
        std::cout << "nope.\n";
    
    return 0;
}
