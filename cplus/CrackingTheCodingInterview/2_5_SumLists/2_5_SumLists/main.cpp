//
//  main.cpp
//  2_5_SumLists
//
//  Created by Lesley Miller on 10/18/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "math.h"

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

long computeLinkedList(node* head)
{
    long l = 0;
    int num = 0;
    while (head)
    {
        l += head->data * pow(10, num);
        num++;
        head = head->next;
    }
    return l;
}

node* convertToLinkedList(long l)
{
    node * head = NULL;

    int num = 1;
    
    while ( l > 0 )
    {
        node * n = (node*) malloc(sizeof(node));
        long p = pow(10, num);

        n->data = (l % p)/pow(10, num-1);
        n->next = head;
        head = n;
        
        l -= l % p;
        num++;
    }
    
    return head;
}



node* sumLists(node *a, node *b)
{
    return convertToLinkedList(computeLinkedList(a) + computeLinkedList(b));
}

//Using recursion
node* sumLists2(node* a, node* b, int &carry)
{
    if ( !a && !b && carry == 0 )
        return NULL;
    
    node *head = (node*) malloc(sizeof(node));
    int a_data = a ? a->data : 0;
    int b_data = b? b->data : 0;
    node* a_next = a ? a->next : NULL;
    node* b_next = b ? b->next : NULL;
    
    head->data = a_data + b_data + carry;
    if ( head->data > 9 )
    {
        head->data -= 10;
        carry = 1;
    }
    else
        carry = 0;
    
    head->next = sumLists2(a_next, b_next, carry);
    
    return head;
    
}

node* sumListsBackwardsHelper(node *a, node *b, int &carry)
{
    if ( a == NULL && b == NULL )
        return NULL;
    
    node* next_a = a ? a->next : NULL;
    node* next_b = b ? b->next : NULL;
    
    
    node* c = sumListsBackwardsHelper(next_a, next_b, carry);
    
    if ( a == NULL && b == NULL )
        return NULL;
    
    //nodes should be on the same level now
    node *head = (node*) malloc(sizeof(node));
    head->data = a->data + b->data + carry;
    if ( head->data > 9 )
    {
        carry = 1;
        head->data -= 10;
    }
    else
        carry = 0;
    
    //add the previous new node to this new head
    head->next = c;
    return head;
}

node* sumListsBackwards(node*a, node*b)
{
    int carry = 0;
    node *c = sumListsBackwardsHelper(a, b, carry);
    if ( carry >  0 )
    {
        node *head = (node*) malloc(sizeof(node));
        head->data = carry;
        head->next = c;
        return head;
    }
    else
        return c;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "This is my first list:\n";
    
    
    node *my_list = NULL;
    insert (&my_list, 6);
    insert (&my_list, 1);
    insert (&my_list, 7);
    
    print(my_list);
    
    
    node *my_list2 = NULL;
    insert (&my_list2, 2);
    insert (&my_list2, 9);
    insert (&my_list2, 5);
    
    std::cout << "\nThis is my second list:\n";
    print(my_list2);
    
    
    std::cout << "\nAdd them together and you get:\n";
    
    print(sumLists(my_list, my_list2));
    
    std::cout << "\nAdd them together using recursion and you get:\n";
    
    int carry = 0;
    print(sumLists2(my_list, my_list2, carry));
    
    std::cout << "\nAdd them together backwards and you get:\n";
    
    print(sumListsBackwards(my_list, my_list2));
    
    
    return 0;
}




