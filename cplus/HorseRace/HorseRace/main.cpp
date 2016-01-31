//
//  main.cpp
//  HorseRace
//
//  Created by Lesley Miller on 6/6/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//
//  not finished

#include <iostream>
#include <vector>
#define RACE_SIZE 5


void sort(int count, std::vector<int> list){
    
    for ( int i = 0; i < count-1; i++ )
    {
        for ( int j = i; j > 0; j-- )
        {
            if ( list[j+1] > list[j] )
                break;
            std::swap(list[j], list[j+1]);
        }
    }
}



int race(int count, const char * horses) {
    
    int i = 0, races = 0;
    //const char * top_horses;
    
    int sub_races = count % 5 == 0 ? count/5 : count/5 + 1;
    int top_race_size = (count/5) * 3 + count % 5;
    
    std::vector<int> top_horses;
    
    for ( int i = 0; i < count; i++)
    {
        //get the next 5 or whatever's left
        int subrace_size = i > 5 ? i - 5 : i;
        std::vector<int> subrace(subrace_size);
        for ( int j = 0; j < subrace_size; j++ )
            subrace[j] = horses[i+j];
        
        //get the top 3 horses and add to the top horse list
        sort(subrace_size, subrace);
        for ( int j = 0; j < 3 && j < subrace_size; j++ )
            top_horses.push_back(subrace[j]);
        
        races ++;
    }
    
    //race the top horses
    races += race(top_count, top_horses);
    return races;
}

int main(int argc, const char * argv[]){
    
    std::cout << "How many races to identify the top 3?\n";
    
    
    

    return 0;
}
