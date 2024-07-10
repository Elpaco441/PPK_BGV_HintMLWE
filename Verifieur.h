#include <iostream>
#include <helib/helib.h>
#include <random>


//On veut employer les méthodes de la bibliothèque helib 
using namespace helib;
using namespace std;
using namespace NTL;


class Verifieur
{
    const Context& context;
    const PubKey&  pubKey;
    const Ctxt& ctxt;

    public: 

    //Constructeur
    Verifieur(const PubKey& publickey, const Ctxt& cypher);
    
    //Fonction en charge de générer les monomes gammas 
    void genere_monomes(vector<NTL::ZZX> gamma, int exposant_max);

    //Fonction de vérification de l'algo
    bool verification(vector<Ptxt<BGV>> v, vector<vector<DoubleCRT>> e_z, vector<DoubleCRT> r_z, vector<double> r_bound_z, vector<vector<NTL::xdouble>> e_bound_z, vector<Ctxt> w);

};