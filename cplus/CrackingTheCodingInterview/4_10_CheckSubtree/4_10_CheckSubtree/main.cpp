//
//  main.cpp
//  4_10_CheckSubtree
//
//  Created by Lesley Miller on 12/19/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "list"
using namespace std;


template<class T>
struct node{
    node<T>* left = NULL;
    node<T>* right = NULL;
    node<T>* parent = NULL;
    T data;
};

node<char>* buildTestTree()
{
    node<char> *T1_head = new node<char>;
    T1_head->data = 'a';
    
    node<char> *T1_1 = new node<char>;
    T1_1->data = 'b';
    
    node<char> *T1_2 = new node<char>;
    T1_2->data = 'c';
    
    node<char> *T1_3 = new node<char>;
    T1_3->data = 'd';
    
    node<char> *T1_4 = new node<char>;
    T1_4->data = 'e';
    
    node<char> *T1_5 = new node<char>;
    T1_5->data = 'f';
    
    node<char> *T1_6 = new node<char>;
    T1_6->data = 'g';
    
    node<char> *T1_7 = new node<char>;
    T1_7->data = 'h';
    
    node<char> *T1_8 = new node<char>;
    T1_8->data = 'i';
    
    node<char> *T1_9 = new node<char>;
    T1_9->data = 'j';
    
    node<char> *T1_10 = new node<char>;
    T1_10->data = 'k';
    
    node<char> *T1_11 = new node<char>;
    T1_11->data = 'a';
    
    node<char> *T1_12 = new node<char>;
    T1_12->data = 'c';
    
    node<char> *T1_13 = new node<char>;
    T1_13->data = 'g';
    
    node<char> *T1_14 = new node<char>;
    T1_14->data = 'f';
    
    node<char> *T1_15 = new node<char>;
    T1_15->data = 'a';
    
    node<char> *subtree = new node<char>;
    subtree->data = 'a';
    
    node<char> *T1_17 = new node<char>;
    T1_17->data = 'b';
    
    node<char> *T1_18 = new node<char>;
    T1_18->data = 'c';
    
    node<char> *T1_19 = new node<char>;
    T1_19->data = 'b';
    
    node<char> *T1_20 = new node<char>;
    T1_20->data = 'c';
    
    node<char> *T1_21 = new node<char>;
    T1_21->data = 'g';
    
    node<char> *T1_22 = new node<char>;
    T1_22->data = 'f';
    
    T1_head->left = T1_1; T1_head->right = T1_2;
    T1_1->left = T1_3; T1_1->right = T1_4;
    T1_3->left = T1_12; T1_3->right = T1_6;
    T1_12->left = T1_5; T1_12->right = T1_11;
    T1_2->left = T1_14; T1_2->right = T1_13;
    T1_13->left = T1_8; T1_13->right = T1_7;
    T1_14->left = T1_9;
    T1_9->right = T1_10;
    T1_4->left = T1_15; //T1_4->right = subtree;
    T1_15->left = T1_17; T1_15->right = T1_18;
    subtree->left = T1_19; subtree->right = T1_20;
    T1_18->left = T1_22; T1_18->right = subtree;//T1_21;
    return T1_head;
}

template <class T>
bool isCandidate(node<T> *T1, node<T> *T2)
{
    if ( !T1 && !T2 ) return true;
    if ( !T1 || !T2 ) return false;
    if ( T1->data != T2->data ) return false;
    
    if ( !T1->left && !T2->left ) return true;
    if ( !T1->left || !T2->left ) return false;
    if ( T1->left->data != T2->left->data ) return false;
    
    if ( !T1->right && !T2->right ) return true;
    if ( !T1->right || !T2->right ) return false;
    if ( T1->right->data != T2->right->data ) return false;
    
    return true;
}

template <class T>
bool checkSubtree(node<T> *T1, node<T> *T2_head, list< node<T>* > &candidates)
{
    //if ( !T1 && !T2_head ) return true;
    //if ( !T1 || !T2_head ) return false;

    bool candidate = isCandidate(T1, T2_head);
    if ( candidate )
        candidates.push_back(T2_head);

    
    list< node<T>* > candidates_left, candidates_right;
    
    for (typename list< node<T>* >::iterator it = candidates.begin(); it != candidates.end(); it++ )
    {
        if(!isCandidate(T1, *it))
        {
            candidates.erase(it);
            continue;
        }
        
        if ( !T1->left && !T1->right && !(*it)->left && !(*it)->right )
            continue;
        
        if ( (*it)->left )
            candidates_left.push_back((*it)->left);
        
        if ( (*it)->right )
            candidates_right.push_back((*it)->right);

    }
    
    if ( T1->left && checkSubtree(T1->left, T2_head, candidates_left) )
        return true;
    
    //remove non viables from the candidate list
    for (typename list< node<T>* >::iterator it = candidates.begin(); it != candidates.end(); it++ )
    {
        if ( (*it)->left )
        {
            if ( !candidates_left.front() || candidates_left.front() != (*it)->left  )
                candidates.erase(it);

        }
    }
    
    if ( T1->right && checkSubtree(T1->right, T2_head, candidates_right) )
        return true;
    
    //remove non viables from the candidate list
    for (typename list< node<T>* >::iterator it = candidates.begin(); it != candidates.end(); it++ )
    {
        if ( (*it)->right )
        {
            if ( !candidates_right.front() || candidates_right.front() != (*it)->right  )
                candidates.erase(it);
            
        }
    }
    
    if ( candidate && candidates.back() == T2_head )
        return true;
    
    return false;
    
}

int main(int argc, const char * argv[]) {
    // insert code here...
    
    node<char> *T1_head = buildTestTree();
    
    
    node<char> *T2_head = new node<char>;
    T2_head->data = 'a';
    node<char> *T2_1 = new node<char>;
    T2_1->data = 'b';
    node<char> *T2_2= new node<char>;
    T2_2->data = 'c';
    
    T2_head->right = T2_2; T2_head->left = T2_1;
    
    list< node<char>* > the_list;
    
    if ( checkSubtree(T1_head, T2_head, the_list) )
        cout << "T1 is a subtree of T2\n";
    else
        cout << "T1 is not a subtree of T2\n";
    
    return 0;
}
