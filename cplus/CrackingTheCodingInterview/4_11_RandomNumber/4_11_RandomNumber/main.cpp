//
//  main.cpp
//  4_11_RandomNumber
//
//  Created by Lesley Miller on 12/21/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <random>
using namespace std;


template<class T>
struct node{
    node<T>* left = NULL;
    node<T>* right = NULL;
    T data;
};

template <class T>
node<T>* getNode(node<T> *head, int &current, int requested)
{
    if ( !head ) return NULL;
    if ( current == requested ) return head;
    
    if ( head->left )
    {
        current++;
        node<T> *found = getNode(head->left,current, requested);
        if ( found )
            return found;
    }
    
    if ( head->right )
    {
        current++;
        node<T> *found = getNode(head->right,current, requested);
        if ( found )
            return found;
    }
    
    return NULL;
}

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
    
    node<char> *T1_16 = new node<char>;
    T1_16->data = 'a';
    
    node<char> *T1_17 = new node<char>;
    T1_17->data = 'b';
    
    node<char> *T1_18 = new node<char>;
    T1_18->data = 'c';
    
    node<char> *T1_19 = new node<char>;
    T1_19->data = 'b';
    
    node<char> *T1_20 = new node<char>;
    T1_20->data = 'c';
    
    node<char> *T1_21 = new node<char>;
    T1_21->data = 'f';
    
    T1_head->left = T1_1; T1_head->right = T1_10;
    T1_1->left = T1_2; T1_1->right = T1_7;
    T1_2->left = T1_3; T1_2->right = T1_6;
    T1_3->left = T1_4; T1_3->right = T1_5;
    T1_7->left = T1_8; T1_7->right = T1_9;
    T1_10->left = T1_11; T1_10->right = T1_16;
    T1_11->left = T1_12; T1_11->right = T1_15;
    T1_12->left = T1_13; T1_12->right = T1_14;
    T1_16->left = T1_17; T1_16->right = T1_18;
    T1_18->left = T1_19; T1_18->right = T1_20;
    T1_20->left = T1_21;
    

    return T1_head;
}

int main(int argc, const char * argv[]) {
    node<char> *head = buildTestTree();
    
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<int> uni(0,21);
    int requested = uni(rng);
    int current = 0;
    
    node<char> *node = getNode(head, current, requested);
    if ( node )
    {
        cout << "found node " << requested << " which is = " << node->data << "\n";
    }
    else
    {
        cout << "did not find node " << requested << "\n";
    }
    
    return 0;
}
