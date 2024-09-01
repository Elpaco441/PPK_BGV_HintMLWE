#include <iostream>
#include <helib/helib.h>
#include "Structure.h"
#include <random>


//On veut employer les méthodes de la bibliothèque helib 
using namespace helib;
using namespace std;
using namespace NTL;


class Verifieur
{
    const Context& context;
    const PubKey&  pubKey;
    Ctxt& chiffre;

    public: 

    //Constructeur

    Verifieur(const PubKey& publickey);
    
    // Setters getters 
    
    void set_ctxt(const Ctxt& c);

    Ctxt get_ctxt();
    
    //Fonction en charge de générer les monomes gammas 
    void genere_monomes(vector<NTL::ZZX> gamma, int exposant_max);

    //Fonction de vérification de l'algo
    bool verification(double l, vector<NTL::ZZX> gamma,vector<Ptxt<BGV>> messages_preuves, vector<random_chiffrement> randoms_preuves, vector<Ctxt> chiffres_tests);

};