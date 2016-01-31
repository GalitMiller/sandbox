//
//  main.cpp
//  ReverseList
//
//  Created by Lesley Miller on 7/3/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <list>

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

/*void reverse ( node **list )
{
    node * prev = NULL;
    node * next = NULL;
    node * current = *list;
    
    while ( current )
    {
        //set next to the next node in the list
        next = current->next;
        //update the pointer to the previous node
        current->next = prev;
        //save current as the first node in the list
        prev = current;
        //move the loop to the next node
        current = next;
    }
    
    //update the list to point to the last node in the list
    *list = prev;
}*/

void reverse(node** n)
{
    node *prev = NULL;
    node *current = *n;
    node *next = NULL;
    
    while ( current )
    {
        next = current->next;
        current->next = prev;
        prev = current;
        current = next;
    }
    
    *n = prev;
}


int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "Reverse this list:\n";
    
    std::list <const char*> the_list;
    
    for ( int i = 1; i < argc; i++ )
    {
        std::cout << argv[i] << '\n';
        the_list.push_back(argv[i]);
    }
    
    std::cout << "\nThe list in reverse:\n";
    
    the_list.reverse(); //can't access pointers to reverse using std::list
    
    for ( std::list <const char*>::iterator it = the_list.begin(); it != the_list.end(); it++ )
    {
        std::cout << *it << "\n";
    }
    
    //now for a homemade reverse
    node *my_list = NULL;
    for ( int i = 1; i < argc; i++ )
    {
        insert (&my_list, std::atoi(argv[i]));
    }
    
    //homemade list
    std::cout << "\nThe my homemade list:\n";
    print(my_list);
    
    std::cout << "\nMy list in reverse:\n";
    reverse (&my_list);
    print(my_list);
    
    return 0;
}
