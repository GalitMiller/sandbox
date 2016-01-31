//
//  main.cpp
//  4_7_BuildOrder
//
//  Created by Lesley Miller on 12/14/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <list>
#include <array>

struct node {
    std::list<node*> deps;
    bool done = false;
    char name;
};

struct dep {
    char p;
    char c;
};

node* findNode(std::list<node*> list, char n)
{
    for ( std::list<node*>::iterator it = list.begin(); it != list.end(); it++ )
    {
        if ( (*it)->name == n )
            return *it;
    }
    
    return NULL;
}

node* BuildGraph(std::list<char> projects, std::list< dep > deps)
{
    node* head = new node;
    for ( std::list<char>::iterator it = projects.begin(); it != projects.end(); it++ )
    {
        node* child = new node;
        child->name = *it;
        head->deps.push_back(child);
    }
    
    for ( std::list< dep >::iterator it = deps.begin(); it != deps.end(); it++ )
    {
        
        node *p = findNode(head->deps, (*it).p);
        node *c = findNode(head->deps, (*it).c);
        
        if ( p && c )
        {
            //need to handle potential dups
            p->deps.push_back(c);
        }
    }
    
    return head;
}

void getBuildOrder(node* head, std::list<node*> &list)
{
    if ( !head || head->done )	return;
    
    for ( std::list<node*>::iterator it = head->deps.begin(); it != head->deps.end(); it++ )
        getBuildOrder(*it, list);
    
    list.push_back(head);
    head->done = true;
}

int main(int argc, const char * argv[]) {
    //build dep graph
    std::list<char> project_list;
    project_list.push_back('a');
    project_list.push_back('b');
    project_list.push_back('c');
    project_list.push_back('d');
    project_list.push_back('e');
    project_list.push_back('f');
    
    std::list<dep> dep_list;
    dep d;
    d.p = 'd';
    d.c = 'a';
    dep_list.push_back(d);
    dep d2;
    d2.p = 'b';
    d2.c = 'f';
    dep_list.push_back(d2);
    dep d3;
    d3.p = 'd';
    d3.c = 'b';
    dep_list.push_back(d3);
    dep d4;
    d4.p = 'a';
    d4.c = 'f';
    dep_list.push_back(d4);
    dep d5;
    d5.p = 'c';
    d5.c = 'd';
    dep_list.push_back(d5);
    
    node* head = BuildGraph(project_list, dep_list);
    
    std::list<node*> build_list;
    getBuildOrder(head, build_list);
    
    for ( std::list<node*>::iterator it = build_list.begin(); it != build_list.end(); it++ )
    {
        std::cout << (*it)->name << "\n";
    }
    

    return 0;
}
