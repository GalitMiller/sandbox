//
//  list.h
//  BinarySearchTree
//
//  Created by Lesley Miller on 1/18/22.
//

#ifndef __LinkedList__
#define __LinkedList__

struct node {
    int data;
    node* next;
};

node* listify(int data[], int l);
node* merge( node* listA, node *listB);
void print ( node* list );

#endif /* defined(__LinkedList__) */
