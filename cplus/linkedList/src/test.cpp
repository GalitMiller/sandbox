//
//  test.cpp
//  LinkedList
//
//  Created by Lesley Miller on 1/17/22.
//

#include <iostream>
#include "list.h"
#include "test.h"

void testMerge() {
    int num = 5;
    test tests[] = {
        {
            new int[3] {1,2,4}, 3,
            new int[3] {1,3,4}, 3,
            new int[6] {1,1,2,3,4,4}, 6
        },
        {
            new int[3] {10,20,40}, 3,
            new int[3] {1,3,4}, 3,
            new int[6] {1,3,4,10,20,40}, 6
        },
        {
            new int[3] {1,3,4}, 3,
            new int[3] {10,20,40}, 3,
            new int[6] {1,3,4,10,20,40}, 6
        },
        {
            new int[3] {1,2,4}, 3,
            new int[1] {3}, 1,
            new int[4] {1,2,3,4}, 4
        },
        {
            new int[0] {}, 0,
            new int[1] {3}, 1,
            new int[1] {3}, 1
        }
    };

    for (int i = 0; i < num; i++) {
        bool passed = true;

        test daTest = tests[i];
        node* listA = listify(daTest.a, daTest.lena);
        node* listB = listify(daTest.b, daTest.lenb);

        node* actual = merge(listA, listB);

        int t = 0;
        while (actual && passed) {
            if (t >= daTest.lene) {
                passed = false;
                // std::cout << "Test " << i << ": ";
                // std::cout << "expected len " << daTest.lene << " actual " << t <<  "\n";
            } else if (actual->data != daTest.e[t]) {
                passed = false;
                // std::cout << "Test " << i << ": ";
                // std::cout << "expected " << daTest.e[t] << " actual " << actual->data << "\n";
            } else {
                actual = actual->next;
                t++;
            }
        }

        passed = passed && actual == NULL && t == daTest.lene;
        std::cout << "Test " << i << ": ";
        std::cout << (passed ? "passed" : "failed") << "\n";
    }
}
