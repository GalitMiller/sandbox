//
//  main.cpp
//  BinarySearchTree
//
//  Created by Lesley Miller on 7/4/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//
//  implements a binary search tree

#include <iostream>
#include "Tree.h"

int main(int argc, const char * argv[]) {

    std::cout << "building a binary search tree using these terms:\n";
    
    Tree *the_tree = NULL;
    
    for ( int i = 1; i < argc; i++ )
    {
        int data = atoi(argv[i]);
        std::cout << data << "\n";
        if ( !the_tree )
            the_tree = new Tree(data);
        else
            the_tree->insert(data);
    }
    
    //test
    std::cout << "the smallest term in the tree is " << the_tree->findSmallestData() << "\n";
    
    //test insert
    the_tree->insert(2);
    std::cout << "the smallest term in the tree after inserting 2 is " << the_tree->findSmallestData() << "\n";
    
    //test delete
    the_tree->remove(2);
    std::cout << "the smallest term in the tree after removing 2 is " << the_tree->findSmallestData() << "\n";

    the_tree->remove(3);
    std::cout << "the smallest term in the tree after removing 3 is " << the_tree->findSmallestData() << "\n";

    the_tree->remove(5);
    std::cout << "the smallest term in the tree after removing 5 is " << the_tree->findSmallestData() << "\n";
    
    the_tree->remove(6);
    std::cout << "the smallest term in the tree after removing 6 is " << the_tree->findSmallestData() << "\n";

    the_tree->remove(7);
    std::cout << "the smallest term in the tree after removing 7 is " << the_tree->findSmallestData() << "\n";

    the_tree->remove(8);
    std::cout << "the smallest term in the tree after removing 8 is " << the_tree->findSmallestData() << "\n";

    //todo - how to remove the last element?
    the_tree->remove(9);
    std::cout << "the smallest term in the tree after removing 9 is " << the_tree->findSmallestData() << "\n";

    return 0;
}
