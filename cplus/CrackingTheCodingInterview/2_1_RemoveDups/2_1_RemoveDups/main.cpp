//
//  main.cpp
//  2_1_RemoveDups
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

void reverse ( node **list )
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
}

node* remove( node *rem)
{
    node *temp = rem->next;
    delete rem;
    return temp;
}

void removeDuplicates1 ( node **list )
{
    //node * prev = NULL;
    //node * next = NULL;
    node * current = *list;
    bool hash[100] = {false}; //assumption
    node * parent = NULL;
    
    while ( current )
    {
        if ( hash[current->data] )
        {
            current = remove(current);
            continue;
        }
        else
            hash[current->data] = true;
        
        parent = current;
        current = current->next;
    }
    
}

//no extra buffer*****************************
void removeNextDup( node *head)
{
    int data = head->data;
    node* next = head->next;
    node* prev = head;
    while ( next )
    {
        if ( next->data == data )
        {
            prev->next = remove(next);
            return;
        }
        
        prev = next;
        next = next->next;
    }
}

void removeDuplicates2 ( node **list )
{
    node * current = *list;
    node * parent = NULL;
    
    while ( current )
    {
        if ( current->next )
        {
            removeNextDup(current);
            
        }
        
        parent = current;
        if ( current->next )
            current = current->next;
        else
            current = NULL;
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
    
    std::cout << "\nThis is my list without the dups:\n";
    removeDuplicates2 (&my_list);
    
    print(my_list);
    
    return 0;
}

