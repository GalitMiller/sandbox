//
//  main.cpp
//  8_11_Coins
//
//  Created by Lesley Miller on 1/7/16.
//  Copyright © 2016 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "vector"

using namespace std;

template < int num_denoms >
int makeChange(int amount, int denoms[num_denoms], int index)
{
    if ( index >= num_denoms -1 ) return 1; //last denom
    int denomAmount = denoms[index];
    int ways = 0;
    for ( int i = 0; i * denomAmount <= amount; i++ )
    {
        int amountRemaining = amount - i * denomAmount;
        ways += makeChange<num_denoms>(amountRemaining, denoms, index+1);
    }
    return ways;
}


int coinPermutations(int amount, int coin, vector< vector<int> > &permutations, vector<int> current)
{
    if ( coin <= 1 ) return 1;
    
    int ways = 0;
    for ( int i = 0; i * coin <= amount; i++ )
    {
        if ( i > 0 )
        {
            vector<int> new_current(current.begin(), current.end());
            current = new_current;
        }
        
        for ( int j = 0; j <=i; j++ )
            current.push_back(coin);
        
        int amountRemaining = amount - i * coin;
        
        int next_coin;
        if ( coin == 25 ) next_coin = 10;
        else if ( coin == 10 ) next_coin = 5;
        else next_coin = 1;
        
        ways += coinPermutations(amountRemaining, next_coin, permutations, current);
        permutations.push_back(current);
    }
    return ways;
}

int getNextCoin(int coin)
{
    int Q = 25;
    int D = 10;
    int N = 5;
    int P = 1;
    
    if ( coin == Q ) return D;
    if ( coin == D ) return N;
    return P;
}

int countPermutations(int n, int coin, vector< vector <int> > &permutations, vector<int> current)
{
    if ( coin == 1 )
    {
        current.push_back(n);
        permutations.push_back(current);
        return 1;
    }
    
    int ret = 0;
    
    for ( int i = 0; (i * coin) <= n; i++ )
    {
        vector<int> new_combo(current.begin(), current.end());
        new_combo.push_back(i);
        
        int rem = n - ( i * coin );
        int next_coin = getNextCoin(coin);
        ret += countPermutations(rem, next_coin, permutations, new_combo);
    }
    
    return ret;
}

vector< vector<int> > countPermutations(int n)
{
    vector< vector<int> > permutations;
    vector<int> first;
    countPermutations(n, 25, permutations, first);
    return permutations;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "Hello, World!\n";
    
    //int denoms[4] = {25, 10, 5, 1};
    //int ways = makeChange<4>(100, denoms, 0);

    vector< vector<int> > permutations;
    vector<int> current;
    int ways2 = coinPermutations(25, 25, permutations, current);
    permutations = countPermutations(25);
    
    //std::cout << "There are " << ways << " ways to make change for " << 100 << "\n";
    std::cout << "\nmy way:\n";
    std::cout << "There are " << ways2 << " ways to make change for " << 25 << " c\n";
    std::cout << "There are " << permutations.size() << " ways to make change for " << 25 << " c\n";
    
    for (int i = 0; i < permutations.size(); i++)
    {
        for ( int j = 0; j < permutations[i].size(); j++ )
            cout << permutations[i][j] << ", ";
        
        cout << "\n";
    }
    return 0;
}
