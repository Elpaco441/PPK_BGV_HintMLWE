#include <iostream>
#include <helib/helib.h>
#include <random>
#include "Verifieur.h"
#include "Structure.h"


//On veut employer les méthodes de la bibliothèque helib 
using namespace helib;
using namespace std;
using namespace NTL;

//Constructor
Verifieur::Verifieur(const PubKey& publickey) :
    context(publickey.getContext()),
    pubKey(publickey),
    chiffre(*(new Ctxt(pubKey)))
{}

// Setters getters 
void Verifieur::set_ctxt(const Ctxt& c){
    this->chiffre = c;
}

Ctxt Verifieur::get_ctxt(){
    return this->chiffre;
}


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



bool Verifieur::verification(double l, vector<NTL::ZZX> gamma,vector<Ptxt<BGV>> messages_preuves, vector<random_chiffrement> randoms_preuves, vector<Ctxt> chiffres_tests){
    helib::Ctxt result(pubKey);
    for (long j = 0; j < l; ++j){
        pubKey.Encrypt(result, messages_preuves[j], randoms_preuves[j].r, randoms_preuves[j].e, randoms_preuves[j].e_bound, randoms_preuves[j].r_bound);
        Ctxt somme(pubKey);
        somme = chiffre;
        cout << "gamma :" << gamma[j] << endl; 
        somme.parts[0] *= gamma[j];
        somme.parts[1] *= gamma[j];
        somme += chiffres_tests[j];

        DoubleCRT poly1 = result.parts[0];
        DoubleCRT poly2 = somme.parts[0];
        ZZX poly_test1;
        ZZX poly_test2;
        poly1.toPoly(poly_test1);
        poly2.toPoly(poly_test2);

        for (auto i = 0; i < deg(poly_test1)+1; ++i) {
            if (poly_test1[i] + context.getP() == poly_test2[i])
            {
                poly_test1[i] += context.getP();
            }
            else if (poly_test1[i] == poly_test2[i] + context.getP())
            {
                poly_test1[i] -= context.getP();
            }
            else if (poly_test1[i] == poly_test2[i] + 2*context.getP())
            {
                poly_test1[i] -= 2*context.getP();
            }
            else if (poly_test1[i] + 2*context.getP()  == poly_test2[i])
            {
                poly_test1[i] += 2*context.getP();
            }
            else if (poly_test1[i] == poly_test2[i] + 3*context.getP())
            {
                poly_test1[i] -= 3*context.getP();
            }
            else if (poly_test1[i] + 3*context.getP()  == poly_test2[i])
            {
                poly_test1[i] += 3*context.getP();
            }
            else if (poly_test1[i] == poly_test2[i] + 4*context.getP())
            {
                poly_test1[i] -= 4*context.getP();
            }
            else if (poly_test1[i] + 4*context.getP()  == poly_test2[i])
            {
                poly_test1[i] += 4*context.getP();
            }
            else if (poly_test1[i] != poly_test2[i] ){
                cout << "Erreur, la différence est : " << poly_test1[i] - poly_test2[i] << endl;
            }
        };
        DoubleCRT result_CRT = DoubleCRT(poly_test1, context, context.getCtxtPrimes());
        CtxtPart result_ctxt = CtxtPart(result_CRT);
        result.parts[0] = (result_ctxt);

        cout << "Vérification de l'égalité " << j << "..." << endl; 
        

        if (result != somme){
            cout << "La vérification n'a pas fonctionné" << endl;
            return false;
        }

        cout << "Le resulat est bon" << endl;
    }
    cout << "La vérification a fonctionné\n" << endl;
    return true;
}


        