//
//  main.cpp
//  4_4_CheckBalanced
//
//  Created by Lesley Miller on 12/13/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//

#include <iostream>

template <class T>
struct node {
    T data;
    node<T> *left;
    node<T> *right;
};

template <class T>
bool isBalanced(node<T>* head, int &height)
{
    if (!head) return true;
    int left = 0;
    int right = 0;
    if ( ! (isBalanced(head->left, left) && isBalanced(head->right, right)) )
        return false;
    
    height += left > right ? left : right;
    height ++;
    return abs(left-right)<2 ? true : false;
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
    
    child3->left = child1;
    child3->right = NULL;
    child1->right = root;
    root->left = NULL;
    root->right = NULL;
    child1->left = NULL;
    child2->right = NULL;
    child2->left = NULL;
    child6->left = child3;
    child6->right = child2;
    child12->left = child6;
    child12->right = child9;
    child9->left = child8;
    child8->left = NULL;
    child8->right = NULL;
    child9->right = child7;
    child7->right = NULL;
    child7->left = NULL;
    
    return child12;
}

int main(int argc, const char * argv[]) {
    
    node<int>* head = buildTree();
    
    printTree(head);
    
    int height = 0;
    std::cout << (isBalanced(head, height) ? "tree is balanced" : "tree is not balanced") << "\n";
    
    return 0;
}
