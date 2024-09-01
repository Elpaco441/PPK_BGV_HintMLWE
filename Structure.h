// random_chiffrement.h
#ifndef STRUCTURE_H
#define STRUCTURE_H

#include <helib/helib.h>

#include <iostream>

// Ajoutez les autres inclusions nécessaires

struct random_chiffrement {
    helib::DoubleCRT r; 
    double r_bound;
    std::vector<NTL::xdouble> e_bound;
    std::vector<helib::DoubleCRT> e;


    random_chiffrement(const helib::Context& context)
        : r(context,context.getCtxtPrimes()), r_bound(0.0) {}
};



#endif // RANDOM_CHIFFREMENT_H