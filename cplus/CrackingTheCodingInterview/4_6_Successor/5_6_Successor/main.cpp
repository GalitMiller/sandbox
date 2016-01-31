//
//  main.cpp
//  4_6_Successor
//
//  Created by Lesley Miller on 12/13/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//

#include <iostream>

template <class T>
struct node {
    T data;
    node<T> *left = NULL;
    node<T> *right = NULL;
    node<T> *parent = NULL;
};

template <class T>
node<T>* getSuccessor(node<T>* n)
{
    if ( !n ) return NULL;
    if ( n->right ) return n->right;
    return n->data < n->parent->data ? n->parent :n->parent->parent;
}

template <class T>
void printTree(node<T> *head)
{
    if ( !head ) return;
    
    printTree(head->left);
    std::cout << head->data << "\n";
    printTree(head->right);
    
}

int main(int argc, const char * argv[]) {
    node<int> *root = new node<int>;
    root->data = 0;
    node<int> *child1 = new node<int>;
    child1->data = 1;
    node<int> *child5 = new node<int>;
    child5->data = 5;
    node<int> *child3 = new node<int>;
    child3->data = 3;
    node<int> *child4 = new node<int>;
    child4->data = 4;
    node<int> *child2 = new node<int>;
    child2->data = 2;
    node<int> *child12 = new node<int>;
    child12->data = 12;
    node<int> *child6 = new node<int>;
    child6->data = 6;
    node<int> *child9 = new node<int>;
    child9->data = 9;
    node<int> *child8 = new node<int>;
    child8->data = 8;
    node<int> *child7 = new node<int>;
    child7->data = 7;
    
    child6->left = child4;
    child4->parent = child6;
    child6->right = child9;
    child9->parent = child6;
    child4->left = child3;
    child3->parent = child4;
    child4->right = child5;
    child5->parent = child4;
    child3->left = child1;
    child1->parent = child3;
    child9->left = child7;
    child7->parent = child9;
    
    printTree(child6);
    
    node<int> *successor = getSuccessor(child5);
    if ( successor )
        std::cout << "child5 successor = " << successor->data << "\n";
    else
        std::cout << "child5 successor = NULL \n";
    
    successor = getSuccessor(child6);
    if ( successor )
        std::cout << "child6 successor = " << successor->data << "\n";
    else
        std::cout << "child6 successor = NULL \n";
    
    successor = getSuccessor(child9);
    if ( successor )
        std::cout << "child9 successor = " << successor->data << "\n";
    else
        std::cout << "child9 successor = NULL \n";
    
    successor = getSuccessor(child3);
    if ( successor )
        std::cout << "child3 successor = " << successor->data << "\n";
    else
        std::cout << "child3 successor = NULL \n";
    
    successor = getSuccessor(child4);
    if ( successor )
        std::cout << "child4 successor = " << successor->data << "\n";
    else
        std::cout << "child4 successor = NULL \n";
    
    successor = getSuccessor(child1);
    if ( successor )
        std::cout << "child1 successor = " << successor->data << "\n";
    else
        std::cout << "child1 successor = NULL \n";
    
    successor = getSuccessor(child7);
    if ( successor )
        std::cout << "child7 successor = " << successor->data << "\n";
    else
        std::cout << "child7 successor = NULL \n";

    return 0;
}
