//
//  main.cpp
//  4_8_FirstCommonAncestor
//
//  Created by Lesley Miller on 12/15/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <iomanip>
#include "string"

template <class T>
struct node {
    T data;
    node<T> *left = NULL;
    node<T> *right = NULL;
    node<T> *parent = NULL;
};

template <class T>
void printTree(node<T>* p, int indent=0)
{
    if(p != NULL) {
        if(p->left) printTree(p->left, indent+4);
        if(p->right) printTree(p->right, indent+4);
        if (indent) {
            std::cout << std::setw(indent) << ' ';
        }
        std::cout<< p->data << "\n ";
    }
}

template <class T>
bool isDescendent(node<T>* child, node<T>* parent)
{
    if ( !parent || !child ) return false;
    
    if ( parent->right && parent->right == child )
        return true;
    
    if ( parent->left && parent->left == child )
        return true;
    
    return isDescendent(child, parent->left) || isDescendent(child, parent->right);
}

template <class T>
node<T>* findCommonAncestor(node<T>* a, node<T>* b)
{
    if ( a == b )
        return (a->parent? a->parent: NULL);
    
    if ( isDescendent(b, a) )
        return a;
    
    while ( a->parent )
    {
        if ( a->parent == b )
            return a->parent;
        
        if ( a->parent->left && a->parent->left != a )
        {
            if ( a->parent->left == b || isDescendent(b, a->parent->left ) )
                return a->parent;
        }
        
        if ( a->parent->right && a->parent->right != a )
        {
            if ( a->parent->right == b || isDescendent(b, a->parent->right ) )
                return a->parent;
        }
        
        a = a->parent;
    }
    
    return NULL;
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
    
    node<int> *ancestor = findCommonAncestor(child1, child9);
    if ( ancestor )
        std::cout << "\nfound common ancestor = " << ancestor->data << "\n";
    else
        std::cout << "\nno common ancestor found\n";
    
    ancestor = findCommonAncestor(child9, child1);
    if ( ancestor )
        std::cout << "\nsearching the other way = " << ancestor->data << "\n";
    else
        std::cout << "\nno common ancestor found\n";
    
    return 0;
}
