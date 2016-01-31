//
//  main.cpp
//  2_6_Palindrome
//
//  Created by Lesley Miller on 10/21/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "stack"

struct node {
    int data;
    node* next;
};

void insert ( node ** list, int new_data )
{
    
    node* new_node = (node*) malloc( sizeof(node) );
    new_node->data = new_data;
    new_node->next = *list;
    
    *list = new_node;
}

void print ( node *list )
{
    node *current = list;
    
    while (current)
    {
        std::cout << current->data << "\n";
        current = current->next;
    }
}

void reverseSingleLinkedList(node **n)
{
    node* next;
    node* prev = NULL;
    
    while (*n)
    {
        next = (*n)->next;
        (*n)->next = prev;
        prev = *n;
        *n = next;
    }
    
    *n = prev;
}

template <class T>
bool isPalindrome(node* n, std::stack<T> *s, float middle, int &pos)
{
    if ( !n )
        return ( !s || s->empty() ) ? true : false;
    
    if ( pos > middle && s->empty() )
        return false;
    
    if ( pos > middle && ( s->top() != n->data ) )
        return false;
    
    if ( pos < middle )
        s->push(n->data);
    if ( pos > middle )
        s->pop();
    
    pos++;
    return isPalindrome(n->next, s, middle, pos);
}

node* copyAndReverseList(node* n)
{
    if ( !n ) return NULL;
    
    node* prev = NULL;
    node* new_list = new node;
    new_list->data = n->data;
    
    while ( n->next )
    {
        node *next = new node;
        next->data = n->next->data;
        next->next = new_list;
        
        prev = new_list;
        new_list = next;
        
        n = n->next;
    }
    
    return new_list;
}

std::string compareLists(node* a, node* b)
{
    while ( a && b )
    {
        if ( a->data != b->data )
            return "false";
        
        a = a->next;
        b = b->next;
    }
    
    return ( !a && !b ? "true" : "false" );
}

int main(int argc, const char * argv[]) {
    std::cout << "This is my first list:\n";
    
    float last_node = 0;
    node *my_list = NULL;

    insert (&my_list, 0);
    insert (&my_list, 1);
    last_node++;
    insert (&my_list, 1);
    last_node++;
    insert (&my_list, 1);
    last_node++;
    insert (&my_list, 1);
    last_node++;
    insert (&my_list, 1);
    last_node++;
    insert (&my_list, 0);
    last_node++;
    
    print(my_list);
    
    
    std::cout << "\nThis is my new list in reverse:\n";
    node *my_new_list = copyAndReverseList(my_list);
    print(my_new_list);
    
    std::cout << "\nAre these lists the same? " << compareLists(my_list, my_new_list);
    
    std::cout << "\nIn-place palindrome check: ";
    std::stack<int> *the_stack = new std::stack<int>;
    int pos = 0;
    isPalindrome(my_list, the_stack, last_node/2, pos) ? std::cout << "true\n" : std::cout << "false\n";
    
    

    return 0;
}
