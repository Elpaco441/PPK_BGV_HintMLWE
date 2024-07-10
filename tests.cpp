#include <iostream>
#include <helib/helib.h>

//On veut employer les méthodes de la bibliothèque helib 
using namespace helib;
using namespace std;
using namespace NTL;


int main(int argc, char* argv[])
{
    unsigned long m,p;
    unsigned long r = 1;
    unsigned long bits = 500; // 1/secu
    unsigned long c = 3;	
    vector<long> mvec,gens,ords;

    //Test

    //m = 3*11*(31);p = 17;mvec ={11,3,31};gens = {838,683};ords = {10,2};bits= 700;//20 !

    //m = 9455;p = 17;mvec = {31,5,61};gens = {3661,1892};ords = {30,4}; //40 !

    //m=5*7*11*(61); p=17; mvec={11,7,5,61}; gens={2136,3356,14092}; ords={10,6,4};bits=600; //60 !

    //m=7*19*(181); p=17; mvec={19,7,181}; gens={3802,3440,2395}; ords={18,6,5};bits=550; // 80 !

    //m=3*7*(31)*71; p=17; mvec={71,7,3,31}; gens={23437,6604,30815}; ords={70,6,2};bits=600;//92 !

    //m=5*7*(1321); p=17; mvec={7,5,1321}; gens={26421,27742,10571}; ords={6,4,55};bits=700; //100 !!!Pas mal celui là!!!

    //m=5*13*19*(37); p=17; mvec={19,13,5,37}; gens={16836,28121,36557}; ords={18,12,4}; //130

    m = 129; p = 2; 


    Context context = ContextBuilder<BGV>()
                                .m(m)
                                .p(p)
                                .r(1)
                                .bits(300)
                                .c(2)
                                .build();

    // Print the context
    cout << "On est là" << endl;
    //context.printout();

    //On génère les clés
    SecKey secretKey = SecKey(context);
    secretKey.GenSecKey();
    addSome1DMatrices(secretKey);
    const PubKey& publicKey = secretKey;

    // On veut tester si l'encryption de deux chiffrés avec deux randoms différents est le chiffré de la somme de deux random

    Ptxt<BGV> premier_pt(context);
    premier_pt[0] = 1;

    DoubleCRT premier_rand(context, context.getCtxtPrimes());
    double premier_r_bound = premier_rand.sampleSmallBounded();

    

    helib::Ctxt premier_ctxt(publicKey);
    std::pair<std::vector<NTL::xdouble>,std::vector<DoubleCRT>> vecteur1 = publicKey.Encrypt(premier_ctxt, premier_pt, premier_rand, premier_r_bound);

    vector<DoubleCRT> premier_e = vecteur1.second;
    vector<NTL::xdouble> premier_e_bound = vecteur1.first;

    // helib::Ctxt copie_premier_ctxt(publicKey);
    // publicKey.Encrypt(copie_premier_ctxt, premier_pt, premier_rand, premier_e, premier_e_bound, premier_r_bound);


    // cout << "Les deux chiffrés sont identiques :" << (copie_premier_ctxt == premier_ctxt) << endl;
    // cout << "Les deux parties 0 sont identiques :" << (copie_premier_ctxt.parts[0] == premier_ctxt.parts[0]) << endl;
    // cout << "Les deux parties 1 sont identiques :" << (copie_premier_ctxt.parts[1] == premier_ctxt.parts[1]) << endl;

    // helib::Ctxt copie2_premier_ctxt(publicKey);
    // publicKey.Encrypt(copie2_premier_ctxt, premier_pt, premier_rand, premier_e, premier_e_bound, premier_r_bound);

    // cout << "Les deux chiffrés sont identiques :" << (copie2_premier_ctxt == premier_ctxt) << endl;
    // cout << "Les deux parties 0 sont identiques :" << (copie2_premier_ctxt.parts[0] == premier_ctxt.parts[0]) << endl;
    // cout << "Les deux parties 1 sont identiques :" << (copie2_premier_ctxt.parts[1] == premier_ctxt.parts[1]) << endl;  

    // cout << "Les deux copies sont identiques :" << (copie2_premier_ctxt == copie_premier_ctxt) << endl;
    // cout << "Les deux parties 0 sont identiques :" << (copie2_premier_ctxt.parts[0] == copie_premier_ctxt.parts[0]) << endl;
    // cout << "Les deux parties 1 sont identiques :" << (copie2_premier_ctxt.parts[1] == copie_premier_ctxt.parts[1]) << endl;

    Ptxt<BGV> deuxieme_pt(context);
    deuxieme_pt[0] = 2;

    DoubleCRT deuxieme_rand(context, context.getCtxtPrimes());
    double deuxieme_r_bound = deuxieme_rand.sampleSmallBounded();

    
    helib::Ctxt deuxieme_ctxt(publicKey);
    std::pair<std::vector<NTL::xdouble>,std::vector<DoubleCRT>> vecteur2 = publicKey.Encrypt(deuxieme_ctxt, deuxieme_pt, deuxieme_rand, deuxieme_r_bound);

    vector<DoubleCRT> deuxieme_e = vecteur2.second;
    vector<NTL::xdouble> deuxieme_e_bound = vecteur2.first;

    Ctxt somme_pur(publicKey);
    somme_pur = premier_ctxt;
    somme_pur += deuxieme_ctxt;

    Ptxt<BGV> somme_pt(context);
    somme_pt = premier_pt;
    somme_pt += deuxieme_pt;
    
    DoubleCRT somme_rand(context, context.getCtxtPrimes());
    double somme_r_bound = somme_rand.sampleSmallBounded();
    vector<NTL::xdouble> somme_e_bound;
    vector<DoubleCRT> somme_e = premier_e;
    for (size_t i = 0; i < deuxieme_e.size(); ++i) {
        somme_e[i] += deuxieme_e[i];
    }
    somme_rand = premier_rand;
    somme_rand += deuxieme_rand;
    somme_r_bound = premier_r_bound + deuxieme_r_bound;
    
    somme_e_bound = premier_e_bound;
    for (size_t i = 0; i < deuxieme_e_bound.size(); ++i) {
        somme_e_bound[i] += deuxieme_e_bound[i];
    }
    Ctxt somme_ctxt(publicKey);
    publicKey.Encrypt(somme_ctxt, somme_pt, somme_rand, somme_e, somme_e_bound, somme_r_bound);
    
    //On veut créer un polynôme de degré m qui ne contient que des 1 et des 0 et qui contient l'information de s'il faut rajouter ou non p afin que les deux chiffrés soient égaux
    //On veut que le polynôme soit de la forme X^l + X^(l-1) + ... + X + 1

    DoubleCRT poly1 = somme_pur.parts[0];
    DoubleCRT poly2 = somme_ctxt.parts[0];
    ZZX poly_test1;
    ZZX poly_test2;
    poly1.toPoly(poly_test1);
    poly2.toPoly(poly_test2);
    vector<long> poly_contrôle(deg(poly_test1),  0);

    for (auto i = 0; i < deg(poly_test1)+1; ++i) {
        if ( poly_test1[i] == poly_test2[i]){
            poly_contrôle[i] = 0;
            cout << "0" << endl;

        }
        else if (poly_test1[i] + p == poly_test2[i])
        {
            poly_contrôle[i] = 1;
            poly_test1[i] += p;
            cout << "1" << endl;
        }
        else if (poly_test1[i] == poly_test2[i] + p)
         {
            poly_contrôle[i] = -1;
            poly_test1[i] -= p;
            cout << "-1" << endl;
        }
        else{
            cout << "Erreur" << endl;
        }
    };
    DoubleCRT result = DoubleCRT(poly_test1, context, context.getCtxtPrimes());
    CtxtPart result_ctxt = CtxtPart(result);
    somme_pur.parts[0] = (result_ctxt);
    


   

    cout << "Le premier chiffré et le deuxième chiffré sont identiques :" << (deuxieme_ctxt == premier_ctxt) << endl;
    cout << "La première partie du premier chiffré et la première partie du deuxième chiffré sont identiques :" << (deuxieme_ctxt.parts[0] == premier_ctxt.parts[0]) << endl;
    cout << "La deuxième partie du premier chiffré et la deuxième partie du deuxième chiffré sont identiques :" << (deuxieme_ctxt.parts[1] == premier_ctxt.parts[1]) << endl;
    cout << "Les deux chiffrés sont identiques :" << (somme_ctxt == somme_pur) << endl;
    cout << "Les deux parties 0 sont identiques :" << (somme_pur.parts[0] == somme_ctxt.parts[0]) << endl;
    cout << "Les deux parties 1 sont identiques :" << (somme_pur.parts[1] == somme_ctxt.parts[1]) << endl;


    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /* On veut tester les opérations de base tel que la somme avec un autre chiffré et la multiplication avec un monome 

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    
     //Génération des l gammas monomes 

    long k = 5; // Degré du monôme
    NTL::ZZX monomial;
    monomial.SetLength(k + 1);
    monomial[k] = 1; // X^k

    // Représentation du monôme avec DoubleCRT
    helib::DoubleCRT dcrt(monomial, context, context.getCtxtPrimes());

    ZZX somme_poly;
    somme_poly = deuxieme_pt.getPolyRepr();
    somme_poly *= monomial;
    Ptxt<BGV> somme_pt(context,somme_poly);

    somme_pt += premier_pt;
    
    deuxieme_rand *= dcrt; 
    deuxieme_rand += premier_rand;
    deuxieme_e *= dcrt;
    deuxieme_e += premier_e;
    for (size_t i = 0; i < deuxieme_e_bound.size(); ++i) {
        deuxieme_e_bound[i] += premier_e_bound[i];
    }
    deuxieme_r_bound += premier_r_bound;

    helib::Ctxt somme_ctxt(publicKey);
    publicKey.Encrypt(somme_ctxt, somme_pt, deuxieme_rand, deuxieme_e, deuxieme_e_bound, deuxieme_r_bound);

    deuxieme_ctxt.parts[1] *= dcrt;
    deuxieme_ctxt += premier_ctxt;

    cout << "Les deux ctxt sont identiques :" << (deuxieme_ctxt.parts[1]==somme_ctxt.parts[1]) << endl;

    */













   // Somme des deux chiffrés

    // cout << "Les deux e sont identiques :" << (copie_e == e) << endl;
    // cout << "Les deux rand sont identiques :" << (copie_rand == rand) << endl;
    // cout << "Les deux r_bound sont identiques :" << (r_bound_copie == r_bound) << endl;
    // cout << "Les deux e_bound sont identiques :" << (e_bound_copie == e_bound) << endl;
    // cout << "\n \n" << endl;

    // copie_e = e;
    // copie_rand = rand;
    // r_bound_copie = r_bound;
    // e_bound_copie = e_bound;

    /*
    cout << "Les deux e sont identiques :" << (copie_e == e) << endl;
    cout << "Les deux rand sont identiques :" << (copie_rand == rand) << endl;
    cout << "Les deux r_bound sont identiques :" << (r_bound_copie == r_bound) << endl;
    cout << "Les deux e_bound sont identiques :" << (e_bound_copie == e_bound) << endl;
    cout << "\n \n" << endl;
    */

    // helib::Ctxt ctxtS(publicKey);
    // ctxtS = ctxt2;
    // ctxtS += ctxt_p;
    //Chiffré correspondant à la somme des deux chiffrés
    
    //Résultats du déchiffrement de la différence des chiffrés
    //secretKey.Decrypt(result, ctxtD);
    //cout << "Déchiffrement de la différence des chiffés" << result << endl;

    /*

    if (ctxt2.parts[0] == ctxt1.parts[0])
        std::cout << "Les deux messages sont égaux" << std::endl;
    else
        std::cout << "Les deux messages sont différents" << std::endl;
    */
}

// Commande d'éxecution : g++ -std=c++17 -I/usr/local/helib_pack/include/ algo.cpp -o algo -L/usr/local/helib_pack/lib -L/usr/local/lib -lhelib -lntl