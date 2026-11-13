#include "../include/interface.hpp"
#include "../include/ipv4.hpp"

#include <iostream>
#include <vector>
 
using namespace std;

vector<interface> allInterfaces;


bool isLocal(uint32_t destinationIPAddr){
     for(size_t i = 0; i < allInterfaces.size(); i++){
          if (allInterfaces[i].interfaceIpAddr == destinationIPAddr)
          {
               return true;
          }  
     }
     return false;
}

