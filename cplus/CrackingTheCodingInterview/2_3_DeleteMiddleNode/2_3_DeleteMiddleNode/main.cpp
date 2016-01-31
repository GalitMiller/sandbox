//
//  main.cpp
//  2_3_DeleteMiddleNode
//
//  Created by Lesley Miller on 10/18/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>



struct node {
    int data;
    node* next;
};

void insert ( node ** list, int new_data )
{
    
    node* new_node = (node*) malloc( sizeof(node) );
    new_node->data = new_data;
    new_node->next = *list;
    
    *list = new_node;
}

void print ( node *list )
{
    node *current = list;
    
    while (current)
    {
        std::cout << current->data << "\n";
        current = current->next;
    }
}

//void DeleteMiddleNode( node* node )
//{
//    if ( !node->next )
//    {
//        delete node;
//        node = NULL;
//    }
//    else
//    {
//        
//        node* next = node->next;
////        node* next = node->next;
////        node->next = next->next;
////        node->data = next->data;
//        delete next;
//    }
//}

void deleteMiddleNode( node* node )
{
    if ( !node->next )
    {
        free( node );
        node = NULL;
    }
    else
    {
        node->data = node->next->data;
        node->next = node->next->next;
    }
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "This is my list:\n";
    
    
    node *my_list = NULL;
    for ( int i = 1; i < argc; i++ )
    {
        insert (&my_list, std::atoi(argv[i]));
    }
    print(my_list);
    
    std::cout << "\nThis is my list after deleting the 5th element:\n";
    deleteMiddleNode(my_list->next->next->next->next);
    print(my_list);
    
    
    return 0;
}


