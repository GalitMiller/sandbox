//
//  main.cpp
//  mergeSortedFiles
//
//  Created by Lesley Miller on 9/18/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "fstream"
#include "string"

//first the simple case
std::string mergeFiles(std::string filepatha, std::string filepathb)
{
    std::fstream filea(filepatha, std::fstream::in);
    std::fstream fileb(filepathb, std::fstream::in);
    std::fstream filec;
    filec.open("/Users/Lesley/Documents/work/projects/mergeSortedFiles/filec.txt", std::fstream::out);
    
    if ( !filea.is_open() || !fileb.is_open() || !filec.is_open() )
        return "";
    
    std::string a,b;
    
    std::getline(fileb, b);
    std::getline(filea, a);
    
    while ( fileb || filea )
    {
        if ( !filea )
        {
            filec << b << "\n";
            std::getline(fileb,b);
        }
        else if ( !fileb )
        {
            filec << a << "\n";
            std::getline(filea,a);
        }
        else
        {
            if ( a.compare(b) < 0 )
            {
                filec << a << "\n";
                std::getline(filea, a);
            }
            else
            {
                filec << b << "\n";
                std::getline(fileb, b);
            }
            
        }
    }
    
    filea.close();
    fileb.close();
    filec.close();
    
    return "filec.txt";
}

//for n files
std::string mergeAllFiles(std::string directory)
{
    //get a list of files in the directory
    
    //exit -- if directory == 2 call merge on the two files, return the resulting file
    //exit -- if directory == 1 return the file;
    
    //split into two lists
    
    //call mergeAllFiles once with each list 
    
    return "";
}

int main(int argc, const char * argv[]) {
    // insert code here...
    if (argc < 3 )
        return 0;
    
    std::string filenamea = argv[1];
    std::string filenameb = argv[2];
    std::cout << "merging files " << filenamea << " and " << filenameb << "\n";
    
    std::string filenamec = mergeFiles(filenamea, filenameb);
    std::cout << "merged filename = " << filenamec;
    return 0;
}
