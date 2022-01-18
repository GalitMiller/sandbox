//
//  merge.cpp
//  LinkedList
//
//  Created by Lesley Miller on 1/17/22.
//

#include <iostream>
#include "list.h"

void insert ( node** list, int new_data )
{
    node* new_node = (node*) malloc( sizeof(node) );
    new_node->data = new_data;
    new_node->next = *list;

    *list = new_node;
}

node* listify(int data[], int l)
{
    node * head = NULL;

    int i = l - 1;
    while ( i >= 0 )
    {
        node * n = (node*) malloc(sizeof(node));
        n->data = data[i];
        n->next = head;
        head = n;
        i--;
    }

    return head;
}

void print ( node* list )
{
    node* current = list;

    while (current)
    {
        std::cout << current->data << "\n";
        current = current->next;
    }
}

// this will mutate the original lists
node* merge( node* listA, node *listB)
{
    if (!listA) return listB;
    if (!listB) return listA;

    node* head = NULL;

    // start list with the smallest value
    if (listA->data < listB->data) {
        head = listA;
        listA = listA->next;
    } else {
        head = listB;
        listB = listB->next;
    }

    // sort the rest of the lists
    node* current = head;
    while (listA && listB) {
        if (listA->data < listB->data) {
            current->next = listA;
            listA = listA->next;
        } else {
            current->next = listB;
            listB = listB->next;
        }
        current = current->next;
    }

    if (listA) {
        current->next = listA;
    } else if (listB) {
        current->next = listB;
    }

    return head;
}
