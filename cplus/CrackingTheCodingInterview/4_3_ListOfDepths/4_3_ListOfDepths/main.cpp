//
//  main.cpp
//  4_3_ListOfDepths
//
//  Created by Lesley Miller on 12/4/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "list"
#include "vector"

template <class T>
struct node {
    T data;
    node<T> *left;
    node<T> *right;
};

template <class T>
void buildList(node<T> *head, std::list<T> &node_list, int depth, int current)
{
    if ( !head )
        return;
    
    if ( current == depth )
        node_list.push_back(head->data);
    else
    {
        buildList(head->left, node_list, depth, current+1);
        buildList(head->right, node_list, depth, current+1);
    }
}

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

template <class T>
void printList(std::list<T> the_list)
{
    for ( typename std::list<T>::iterator it = the_list.begin(); it != the_list.end(); it++ )
    {
        std::cout << *it << "\n";
    }
}

template <class T>
void listAtDepth(node<T> *head, std::list<T> &value_list, int depth)
{
    buildList(head, &value_list, depth, 0);
}

template <>
void listAtDepth(node<int> *head, std::list<int> &value_list, int depth)
{
    buildList(head, value_list, depth, 0);
}

template <class T>
std::list<T> listAtDepth(node<T> *head, int depth)
{
    std::list<T> node_list;
    int current = 0;
    buildList(head, &node_list, depth, current);
    return node_list;
}

//take 2. Modification of tree traversal
template <class T>
void buildLists(node<T> *head, std::vector< std::list<T> > &map, int depth)
{
    if ( !head ) return;
    if ( map.size() <= depth )
    {
        std::list<T> new_list;
        map.push_back(new_list);
    }
    map[depth].push_back(head->data);
    buildLists(head->left, map, depth+1);
    buildLists(head->right, map, depth+1);
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
    
    std::list<int> list_at_depth0;
    listAtDepth(head, list_at_depth0, 0);
    std::cout << "\nlist at depth 0:\n";
    printList(list_at_depth0);
    
    std::list<int> list_at_depth1;
    listAtDepth(head, list_at_depth1, 1);
    std::cout << "\nlist at depth 1:\n";
    printList(list_at_depth1);
    
    std::list<int> list_at_depth2;
    listAtDepth(head, list_at_depth2,  2);
    std::cout << "\nlist at depth 2:\n";
    printList(list_at_depth2);
    
    std::list<int> list_at_depth3;
    listAtDepth(head, list_at_depth3,  3);
    std::cout << "\nlist at depth 3:\n";
    printList(list_at_depth3);
    
    std::cout << "\ntake 2:\n";
    
    std::vector<std::list<int> > map;
    buildLists(head, map, 0);
    
    for ( std::vector<std::list<int> >::iterator it = map.begin(); it != map.end(); it++ )
    {
        printList(*it);
        std::cout<< "\n";
    }
    
    return 0;
}
