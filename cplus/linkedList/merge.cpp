//
//  main.cpp
//  LinkedList
//
//  Created by Lesley Miller on 10/18/15.
//  Copyright (c) 2022 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "math.h"

struct node {
    int data;
    node* next;
};

void insert ( node** list, int new_data )
{
    node* new_node = (node*) malloc( sizeof(node) );
    new_node->data = new_data;
    new_node->next = *list;

    *list = new_node;
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

node* merge( node* listA, node *listB)
{
    if (!listA) return listB;
    if (!listB) return listA;

    node* head = NULL;

    if (listA->data > listB->data) {
        head = listA;
        listA = listA->next;
    } else {
        head = listB;
        listB = listB->next;
    }

    node* current = head;

    while (listA && listB) {
        if (listA->data > listB->data) {
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

bool test( int a[], int lena, int b[], int lenb, int expected[], int lene) {
    node* listA = NULL;
    node* listB = NULL;
    for (int i = 0; i < lena; i++) {
        insert(&listA, a[i]);
    }
    for (int i = 0; i < lenb; i++) {
        insert(&listB, b[i]);
    }

    node* actual = merge(listA, listB);

    int i = lene - 1;
    while (actual) {
        if (i >= lene) return false;
        if (actual->data != expected[i]) return false;
        actual = actual->next;
        i--;
    }

    return actual == NULL && i == -1;
}

int main(int argc, const char* argv[]) {
    // test 1
    int a[3] = {1,2,4};
    int b[3] = {1,3,4};
    int e[6] = {1,1,2,3,4,4};
    bool res = test(a, 3, b, 3, e, 6);
    std::cout << "Test 1: " << (res ? "passed" : "failed") << "\n";

    // test 2
    int a2[3] = {10,20,40};
    int b2[3] = {1,3,4};
    int e2[6] = {1,3,4,10,20,40};
    bool res2 = test(a2, 3, b2, 3, e2, 6);
    std::cout << "Test 2: " << (res2 ? "passed" : "failed") << "\n";

    // test 3
    int a3[3] = {1,3,4};
    int b3[3] = {10,20,40};
    int e3[6] = {1,3,4,10,20,40};
    bool res3 = test(a3, 3, b3, 3, e3, 6);
    std::cout << "Test 3: " << (res3 ? "passed" : "failed") << "\n";

    // test 4
    int a4[3] = {1,2,4};
    int b4[1] = {3};
    int e4[4] = {1,2,3,4};
    bool res4 = test(a4, 3, b4, 1, e4, 4);
    std::cout << "Test 4: " << (res4 ? "passed" : "failed") << "\n";

    // test 4
    int a5[0] = {};
    int b5[1] = {3};
    int e5[4] = {3};
    bool res5 = test(a5, 0, b5, 1, e5, 1);
    std::cout << "Test 5: " << (res5 ? "passed" : "failed") << "\n";

    return 0;
}
