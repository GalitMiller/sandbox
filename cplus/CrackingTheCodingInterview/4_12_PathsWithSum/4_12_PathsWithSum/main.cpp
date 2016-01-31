//
//  main.cpp
//  4_12_PathsWithSum
//
//  Created by Lesley Miller on 12/22/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "list"

template<class T>
struct node{
    node<T>* left = NULL;
    node<T>* right = NULL;
    T data;
};

void pathshWithSum(node<int> *head, int sum, std::list<int> sums, int &count)
{
    if ( !head )
        return;
    
    for (std::list<int>::iterator it = sums.begin(); it != sums.end(); it++)
    {
        if ( (*it) + head->data == sum )
        {
            count++;
            sums.erase(it);
        }
        else
            (*it) += head->data;
    }
    
    sums.push_back(head->data);
   
    pathshWithSum(head->left, sum, sums, count);
    pathshWithSum(head->right, sum, sums, count);

}

node<int>* buildTestTree()
{
    node<int> *T1_head = new node<int>;
    T1_head->data = 25;
    
    node<int> *T1_1 = new node<int>;
    T1_1->data = 15;
    
    node<int> *T1_2 = new node<int>;
    T1_2->data = 10;
    
    node<int> *T1_3 = new node<int>;
    T1_3->data = 4;
    
    node<int> *T1_4 = new node<int>;
    T1_4->data = -3;
    
    node<int> *T1_5 = new node<int>;
    T1_5->data = 5;
    
    node<int> *T1_6 = new node<int>;
    T1_6->data = 12;
    
    node<int> *T1_7 = new node<int>;
    T1_7->data = 22;
    
    node<int> *T1_8 = new node<int>;
    T1_8->data = 18;
    
    node<int> *T1_9 = new node<int>;
    T1_9->data = 24;
    
    node<int> *T1_10 = new node<int>;
    T1_10->data = 50;
    
    node<int> *T1_11 = new node<int>;
    T1_11->data = 35;
    
    node<int> *T1_12 = new node<int>;
    T1_12->data = 31;
    
    node<int> *T1_13 = new node<int>;
    T1_13->data = 30;
    
    node<int> *T1_14 = new node<int>;
    T1_14->data = 32;
    
    node<int> *T1_15 = new node<int>;
    T1_15->data = 44;
    
    node<int> *T1_16 = new node<int>;
    T1_16->data = 70;
    
    node<int> *T1_17 = new node<int>;
    T1_17->data = 66;
    
    node<int> *T1_18 = new node<int>;
    T1_18->data = 90;
    
    node<int> *T1_19 = new node<int>;
    T1_19->data = 80;
    
    node<int> *T1_20 = new node<int>;
    T1_20->data = 95;
    
    node<int> *T1_21 = new node<int>;
    T1_21->data = 94;
    
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

node<int>* buildTestTree2()
{
    node<int> *T1_head = new node<int>;
    T1_head->data = 10;
    
    node<int> *T1_1 = new node<int>;
    T1_1->data = 5;
    
    node<int> *T1_2 = new node<int>;
    T1_2->data = 3;
    
    node<int> *T1_3 = new node<int>;
    T1_3->data = 3;
    
    
    node<int> *T1_6 = new node<int>;
    T1_6->data = -2;
    
    node<int> *T1_7 = new node<int>;
    T1_7->data = 2;
    
    
    node<int> *T1_9 = new node<int>;
    T1_9->data = 1;
    
    node<int> *T1_10 = new node<int>;
    T1_10->data = -3;
    
    
    node<int> *T1_16 = new node<int>;
    T1_16->data = 11;
    
    
    T1_head->left = T1_1; T1_head->right = T1_10;
    T1_1->left = T1_2; T1_1->right = T1_7;
    T1_2->left = T1_3; T1_2->right = T1_6;
    T1_7->right = T1_9;
    T1_10->right = T1_16;
    
    return T1_head;
}

int main(int argc, const char * argv[]) {
    node<int> *head = buildTestTree2();
    int count = 0;
    std::list<int> sums;
    pathshWithSum(head, 8, sums, count);
    std::cout << "found " << count << " paths with that sum\n";
    return 0;
}
