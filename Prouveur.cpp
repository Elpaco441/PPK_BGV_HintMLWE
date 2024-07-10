#include <iostream>
#include <helib/helib.h>
#include <random>


//On veut employer les méthodes de la bibliothèque helib 
using namespace helib;
using namespace std;
using namespace NTL;


Prouveur::Prouveur(const SecKey& secreteKey, const Ptxt& m) :
    context(secreteKey.getContext()),
    pubKey(secreteKey),
    secKey(secreteKey),
    message(m)
{}
    
void Prouveur::addition_p(Ctxt chiffre1, Ctxt chiffre2,ZZX poly_donne){
    DoubleCRT poly1 = chiffre1.parts[0];
    DoubleCRT poly2 = chiffre2.parts[0];
    ZZX poly_test1;
    ZZX poly_test2;
    poly1.toPoly(poly_test1);
    poly2.toPoly(poly_test2);
    poly_contrôle.setLength(deg(poly_test1));
    for (auto i = 0; i < deg(poly_test1)+1; ++i) {
        if ( poly_test1[i] == poly_test2[i]){
            poly_contrôle[i] = 0;
        }
        else if (poly_test1[i] + p == poly_test2[i])
        {
            poly_contrôle[i] = 1;
            poly_test1[i] += p;
        }
        else if (poly_test1[i] == poly_test2[i] + p)
         {
            poly_contrôle[i] = -1;
            poly_test1[i] -= p;
        }
        else{
            cout << "Erreur" << endl;
        }
    };
    DoubleCRT result = DoubleCRT(poly_test1, context, context.getCtxtPrimes());
    CtxtPart result_ctxt = CtxtPart(result);
    chiffre1.parts[0] = (result_ctxt);
}
    
void Prouveur::addition_p(Ctxt chiffre1, Ctxt chiffre2){
    DoubleCRT poly1 = chiffre1.parts[0];
    DoubleCRT poly2 = chiffre2.parts[0];
    ZZX poly_test1;
    ZZX poly_test2;
    poly1.toPoly(poly_test1);
    poly2.toPoly(poly_test2);
    for (auto i = 0; i < deg(poly_test1)+1; ++i) {
        if (poly_test1[i] + p == poly_test2[i])
        {
            poly_contrôle[i] = 1;
            poly_test1[i] += p;
        }
        else if (poly_test1[i] == poly_test2[i] + p)
         {
            poly_contrôle[i] = -1;
            poly_test1[i] -= p;
        }
        else if (poly_test1[i] != poly_test2[i])
        {
            cout << "Erreur" << endl;
        }
    };
    DoubleCRT result = DoubleCRT(poly_test1, context, context.getCtxtPrimes());
    CtxtPart result_ctxt = CtxtPart(result);
    chiffre1.parts[0] = (result_ctxt);
}
    