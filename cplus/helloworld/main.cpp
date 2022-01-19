//
//  main.cpp
//  helloworld
//
//  Created by Lesley Miller on 1/9/22.
//  Copyright (c) 2022 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <string>

using namespace std;

#define PI 3.14159
#define NEWLINE '\n'

int main() {
    int a = 5;
    int b = 2;
    a = a + 1;
    a += 2;
    auto result = a - b;

    int x, y, z = 3;
    x = y = z;
    cout << x << " " << y << " " << z << NEWLINE;

    bool t = true, f = false, m;

    cout << (t || f) << NEWLINE;

    float flt = (float)a;
    cout << flt << "," << a << NEWLINE;

    // cout << "Hello, World! your answer is " << result << NEWLINE;
}
