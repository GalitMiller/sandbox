//
//  Tree.cpp
//  BinarySearchTree
//
//  Created by Lesley Miller on 7/4/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "Tree.h"

Tree* Tree::insert(int data){
    if ( data == _data )
        return this;
    
    if ( data > _data )
    {
        if ( _right )
            return _right->insert(data);
        
        _right = new Tree(data);
        _right->_parent = this;
        return _right;
    }
    else
    {
        if ( _left )
            return _left->insert(data);
        
        _left = new Tree(data);
        _left->_parent = this;
        return _left;
    }
}

Tree* Tree::find(int data){
    if ( data == _data ) return this;
    
    Tree *node = NULL;
    
    if ( _left  )
        node = _left->find(data);
    
    if ( !node && _right )
        node = _right->find(data);
    
    return node;
}

void Tree::remove(int data){
    
    Tree* node = find(data);
    
    if ( node )
        node->remove();
}

void Tree::remove(){
    
    if ( !_right && !_left)
    {
        //removing a leaf node. There is a memory leak here.
        if ( _parent && _parent->_right == this )
            _parent->_right = NULL;
        else if ( _parent && _parent->_left == this )
            _parent->_left = NULL;
    }
    
    else if ( !_right )
    {
        Tree *dead = _left;
        _data = _left->_data;
        _right = _left->_right;
        _left = _left->_left;
        
        //reparent
        if ( _right ) _right->_parent = this;
        if ( _left ) _left->_parent = this;
        delete dead;
    }
    else if ( !_left )
    {
        Tree *dead = _right;
        _data = _right->_data;
        _left = _right->_left;
        _right = _right->_right;
        
        //reparent
        if ( _right ) _right->_parent = this;
        if ( _left ) _left->_parent = this;
        delete dead;
    }
    else
    {
        Tree *next = _right->findLeftmostNode();
        _data = next->_data;
        next->remove();
    }
}

int Tree::findSmallestData()
{
    return findSmallestNode()->_data;
}

Tree* Tree::findSmallestNode()
{

    Tree* small_left = _left? _left->findSmallestNode() : this;
    Tree* small_right = _right? _right->findSmallestNode() : this;
    
    
    if ( small_left->_data < this->_data && small_left->_data < small_right->_data ) return small_left;
    if ( small_right->_data < this->_data && small_right->_data < small_left->_data ) return small_right;
    
    if ( small_left->_data < this->_data && small_left->_data < small_right->_data ) return small_left;
    if ( small_right->_data < this->_data && small_right->_data < small_left->_data ) return small_right;
    
    return this;
}

Tree* Tree::findLeftmostNode()
{
    if ( _left )
        return _left->findLeftmostNode();
    
    return this;
}
