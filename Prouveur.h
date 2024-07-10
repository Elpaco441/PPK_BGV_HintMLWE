#include <iostream>
#include <helib/helib.h>
#include <random>


//On veut employer les méthodes de la bibliothèque helib 
using namespace helib;
using namespace std;
using namespace NTL;


void genere_monomes(vector<NTL::ZZX> gamma, int exposant_max){
    int k;
    for (long i = 0; i < gamma.size(); ++i){
        NTL::ZZX monomial;
        //on veut k aléatoire inférieur à 2*n
        k =  rand() % (2*exposant_max);
        monomial.SetLength(k + 1);
        monomial[k] = 1; // X^k
        gamma[i] = monomial;
    }
}