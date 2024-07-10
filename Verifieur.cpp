#include <iostream>
#include <helib/helib.h>
#include <random>
#include "Verifieur.h"


//On veut employer les méthodes de la bibliothèque helib 
using namespace helib;
using namespace std;
using namespace NTL;

//Constructor
Verifieur::Verifieur(const PubKey& publickey, const Ctxt& cypher) :
    context(publickey.getContext()),
    pubKey(publickey),
    ctxt(cypher)
    

void Verifieur::genere_monomes(vector<NTL::ZZX> gamma, int exposant_max){
    int k;
    for (long i = 0; i < gamma.size(); ++i){
        NTL::ZZX monomial;
        //on veut k aléatoire inférieur à 2*n
        k =  rand() % (2*exposant_max);
        monomial.SetLength(k + 1);
        monomial[k] = 1; // X^k
        gamma[i] = monomial;
    };
}

bool Verifieur::verification(vector<Ptxt<BGV>> v, vector<vector<DoubleCRT>> e_z, vector<DoubleCRT> r_z, vector<double> r_bound_z, vector<vector<NTL::xdouble>> e_bound_z, vector<Ctxt> w){
    helib::Ctxt result(pubKey);
    Ctxt somme(pubKey);
    for (long i = 0; i < v.size(); ++i){
        helib::DoubleCRT dcrt(gamma[i], context, context.getCtxtPrimes()); //On convertit gamma_i en DoubleCRT
        publicKey.Encrypt(result, v[i], r_z[i], e_z[i], e_bound_z[i], r_bound_z[i]);
        somme = ctxt;
        somme.parts[1] *= dcrt;
        somme += w[i];
        cout << "Vérification de l'égalité " << i << "..." << endl; 
        if (result.parts[1] != somme.parts[1]){
            cout << "La vérification n'a pas fonctionné" << endl;
            return false;
        }
    }
    return true
}