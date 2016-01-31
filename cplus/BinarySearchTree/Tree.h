//
//  Tree.h
//  BinarySearchTree
//
//  Created by Lesley Miller on 7/4/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#ifndef __BinarySearchTree__Tree__
#define __BinarySearchTree__Tree__

#include <stdio.h>

class Tree
{
public:
    Tree(int data){
        _data = data;
        _left = NULL;
        _right = NULL;
        _parent = NULL;
    };
    
    bool operator < (Tree* t) { if (t) return _data < t->_data; else return false; };
    bool operator <= (Tree* t) { if (t) return _data <= t->_data; else return false; };
    bool operator > (Tree* t) { if (t) return _data > t->_data; else return false; };
    bool operator >= (Tree* t) { if (t) return _data >= t->_data; else return false; };
    bool operator == (Tree* t) { if (t) return _data == t->_data; else return false; };
    
    Tree* insert(int data);
    Tree* find(int data);
    void remove(int data);
    std::string toString() { return std::to_string(_data); };
    int findSmallestData();
    
private:
    void remove();
    Tree* findSmallestNode();
    Tree* findLeftmostNode();
    
    Tree* _left;
    Tree* _right;
    Tree* _parent;
    int _data;
};

#endif /* defined(__BinarySearchTree__Tree__) */
