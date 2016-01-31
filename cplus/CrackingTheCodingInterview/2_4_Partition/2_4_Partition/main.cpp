//
//  main.cpp
//  2_4_Partition
//
//  Created by Lesley Miller on 10/18/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//


#include <iostream>

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

void partition(node **list, int partition)
{
    node *prev = *list;
    node *next = (*list)->next;
    while ( next )
    {
        if (next->data < partition )
        {
            prev->next = next->next;
            next->next = *list;
            *list = next;
            next = prev->next;
        }	
        else
        {
            prev = next;
            next = next->next;	
        }
    }
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "This is my list:\n";
    
    
    node *my_list = NULL;
    for ( int i = 1; i < argc; i++ )
    {
        insert (&my_list, std::atoi(argv[i]));
    }
    print(my_list);
    
    std::cout << "\nThis is my list after partitioning for 5:\n";
    partition(&my_list, 5);
    print(my_list);
    
    
    return 0;
}



