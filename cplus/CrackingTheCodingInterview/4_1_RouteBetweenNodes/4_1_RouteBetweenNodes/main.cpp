//
//  main.cpp
//  4_1_RouteBetweenNodes
//
//  Created by Lesley Miller on 11/25/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <vector>
#include <queue>

int _map = 0;

template <class T>
struct node
{
    T data;
    std::vector<node*> adjacent;
};

template <class T>
int hashVal(node<T> *n)
{
    return 0;
}

template <>
int hashVal(node<int> *n)
{
    return n->data;
}

template <class T>
void visit(node<T> *n)
{
    int hashval = hashVal(n);
    _map = _map | (1 << hashval);
}

template <class T>
void print(node<T> *n)
{
    std::cout << n->data << "\n";
}

template <class T>
bool visited(node<T> *n)
{
    return _map & (1 << hashVal(n));
}

template <class T>
void printDepthFirstSearch(node<T> *root)
{
    if ( !root || visited(root) )
        return;
    
    visit(root);
    print(root);
    
    
    for ( typename std::vector<node<T> *>::iterator it = root->adjacent.begin(); it != root->adjacent.end(); it++ )
        printDepthFirstSearch(*it);
}

template <class T>
void printBreadthFirstSearch(node<T> *root)
{
    if ( !root )
        return;
    
    std::queue<node<T>*> q;
    
    q.push(root);
    
    while ( !q.empty() )
    {
        node<T> *n = q.front();
        q.pop();
        print(n);
        
        for ( typename std::vector<node<T> *>::iterator it = n->adjacent.begin(); it != n->adjacent.end(); it++ )
        {
            if ( !visited(*it) )
            {
                visit(*it);
                q.push(*it);
            }
            
        }
        
    }
    
    
}

template <class T>
bool depthFirstSearch(node<T> *n, int i)
{
    if ( !n || visited(n) )
        return false;
    visit(n);
    if ( n->data == i )
        return true;
    
    for ( typename std::vector< node<T>* >::iterator it = n->adjacent.begin(); it != n->adjacent.end(); it++ )
    {
        if ( !visited(*it) )
            if ( depthFirstSearch(*it, i) )
                return true;
    }
    
    return false;
}

template <class T>
bool breadthFirstSearch(node<T> *head, int i)
{
    if ( !head ) return false;
    if ( head->data == i ) return true;
    
    std::queue< node<T>* > q;
    visit(head);
    q.push(head);
    while (!q.empty())
    {
        node<T>* n = q.front();
        q.pop();
        
        for ( typename std::vector< node<T> *>::iterator it = n->adjacent.begin(); it != n->adjacent.end(); it++)
        {
            if ( (*it)->data == i ) return true;
            if ( !visited(*it) )
            {
                visit(*it);
                q.push(*it);
            }
        }
    }
    return false;
}

node<int>* buildCharTree()
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
    
    root->adjacent.push_back(child1);
    root->adjacent.push_back(child4);
    root->adjacent.push_back(child5);
    child1->adjacent.push_back(child3);
    child1->adjacent.push_back(child4);
    child2->adjacent.push_back(child1);
    child3->adjacent.push_back(child2);
    child3->adjacent.push_back(child4);
    
    return root;
}



int main(int argc, const char * argv[]) {
    
    
    node<int> *root = buildCharTree();
    
    std::cout << "Print depth first:" << "\n";
    printDepthFirstSearch(root);
    
    std::cout << "\nPrint breadth first:" << "\n";
    _map = 0;
    printBreadthFirstSearch(root);
    
    _map = 0;
    std::cout << "\n Is 4 in this tree? Depth first search says..." << depthFirstSearch(root, 4) << "\n";
    
    _map = 0;
    std::cout << "\n Is 4 in this tree? Breadth first search says..." << breadthFirstSearch(root, 4) << "\n";
    
    _map = 0;
    std::cout << "\n Is 7 in this tree? Depth first search says..." << depthFirstSearch(root, 7) << "\n";
    
    _map = 0;
    std::cout << "\n Is 7 in this tree? Breadth first search says..." << breadthFirstSearch(root, 7) << "\n";
    
    
    return 0;
}

