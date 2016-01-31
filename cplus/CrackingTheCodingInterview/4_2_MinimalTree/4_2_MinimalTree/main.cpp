//
//  main.cpp
//  4_2_MinimalTree
//
//  Created by Lesley Miller on 12/4/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "vector"

template <class T>
struct node {
    T data;
    node<T> *left;
    node<T> *right;
};

template <class T>
node<T>* buildTree(std::vector<T> v, int start, int end)
{
    if  ( end-start < 0 )
        return NULL;
    
    int middle = end-start > 1 ? start + (end-start)/2 : start;
    node<T> *head = new node<T>;
    head->data = v[middle];
    head->left = buildTree(v, start, middle-1);
    head->right = buildTree(v, middle+1, end);
    return head;
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
    
    std::vector<int> v;
    
    v.push_back(1);
    v.push_back(2);
    v.push_back(4);
    v.push_back(7);
    v.push_back(8);
    v.push_back(11);
    v.push_back(13);
    
    
    node<int> *head = buildTree(v, 0, 6);
    
    printTree(head);
    return 0;
}
