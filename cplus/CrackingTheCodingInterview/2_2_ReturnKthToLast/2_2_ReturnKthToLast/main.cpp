//
//  main.cpp
//  2_2_ReturnKthToLast
//
//  Created by Lesley Miller on 10/18/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "list"


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

node* returnKthToLastNode(node* head, int k)
{
    int count = 0;
    node* next = head;
    while ( next )
    {
        count++;
        next = next->next;
    }
    
    next = head;
    for ( int i = 0; i < count-k; i++ )
    {
        next = next->next;
    }
    return next;
}

node* returnKthToLastNode2(node* head, node** kth, int &count, int k)
{
    if ( !head )
        return NULL;
    
    returnKthToLastNode2(head->next, kth, count, k);
    count++;
    if ( count == k )
        *kth = head;
    
    return head;
}

int returnKthToLast(node* head, int k)
{
    //return returnKthToLastNode(head, k)->data;
    node* kth = NULL;
    int count = 0;
    returnKthToLastNode2(head, &kth, count, k);
    return kth->data;
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
    
    std::cout << "\nThe third to last element = " << returnKthToLast(my_list, 3) << "\n";
    
    
    return 0;
}

