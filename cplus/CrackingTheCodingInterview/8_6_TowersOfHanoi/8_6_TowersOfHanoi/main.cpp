//
//  main.cpp
//  8_6_TowersOfHanoi
//
//  Created by Lesley Miller on 1/5/16.
//  Copyright © 2016 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "stack"

using namespace std;

void printStack(stack<int> S)
{
    while (S.size())
    {
        cout << S.top() << " ";
        S.pop();
    }
    cout << "\n";
}

void moveDisks(int n, stack<int> &origin, stack<int> &dest, stack<int> &buffer)
{
    if ( !origin.size() ) return;
    if ( n <= 0 ) return;
    
    moveDisks(n-1, origin, buffer, dest);
    int i = origin.top();
    origin.pop();
    dest.push(i);
    moveDisks(n-1, buffer, dest, origin);
}



int main(int argc, const char * argv[]) {
    stack<int> origin;
    origin.push(10);
    origin.push(9);
    origin.push(8);
    origin.push(7);
    origin.push(6);
    origin.push(5);
    origin.push(4);
    origin.push(3);
    origin.push(2);
    origin.push(1);
    
    stack<int> dest;
    stack<int> buffer;
    
    cout << "origin = " ;
    printStack(origin);
    cout << "\n";
    
    cout << "dest   = " ;
    printStack(dest);
    cout << "\n";
    
    cout << "buffer = " ;
    printStack(buffer);
    cout << "\n";
    
    moveDisks(10, origin, dest, buffer);
    
    cout << "move disks from origin to destination*******************\n";
    
    cout << "origin = " ;
    printStack(origin);
    cout << "\n";
    
    cout << "dest   = " ;
    printStack(dest);
    cout << "\n";
    
    cout << "buffer = " ;
    printStack(buffer);
    cout << "\n";

    return 0;
}
