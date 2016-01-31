//
//  main.cpp
//  4_5_ValidateBST
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
};

template <class T>
bool validateBST(node<T>* head)
{
    if ( ! head ) return true;
    if ( head->left && head->right ) //-5
        if ( head->right->data < head->left->data ) return false;
    
    return validateBST(head->left) && validateBST(head->right);
}

template <class T>
void printTree(node<T> *head)
{
    if ( !head ) return;
    
    printTree(head->left);
    std::cout << head->data << "\n";
    printTree(head->right);
    
}

node<int>* buildTree()
{
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
    
    child6->left = child5;
    child6->right = child9;
    child5->left = child3;
    child5->right = child4;
    child3->left = child1;
    child9->left = child7;
    
    return child12;
}

int main(int argc, const char * argv[]) {
    node<int>* head = buildTree();
    
    printTree(head);
    
    std::cout << (validateBST(head) ? "tree is a BST" : "tree is not a BST") << "\n";
    
    return 0;
}
