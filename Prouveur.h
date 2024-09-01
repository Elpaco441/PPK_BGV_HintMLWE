#include <iostream>
#include <helib/helib.h>
#include <random>
#include "Structure.h"


//On veut employer les méthodes de la bibliothèque helib 
using namespace helib;
using namespace std;
using namespace NTL;


class Prouveur
{
    const Context& context;
    PubKey&  pubKey;
    SecKey& secKey;
    const Ptxt<BGV>& message;
    Ctxt& chiffre;
    random_chiffrement& random;
    
    public:


    //Constructeur
    
    Prouveur(const Context& contexte, const Ptxt<BGV>& mess);


    //Getter & setter 

    SecKey& get_secKey() ;

    PubKey& get_pubKey() ;

    Ptxt<BGV> get_ptxt();

    void set_ctxt(const Ctxt& c);

    Ctxt get_ctxt();

    void set_random_de_chiffrement(const DoubleCRT r, const double& r_b, const vector<NTL::xdouble>& e_b, const vector<DoubleCRT>& e );

    random_chiffrement get_random_de_chiffrement();


    //Fonctions 

    void ecrire_random_de_chiffrement();

    Ctxt generation_du_chiffre();

    void generation_des_tests(long l, vector<Ptxt<BGV>> messages_tests, vector<random_chiffrement> randoms_tests, vector<Ctxt> chiffres_tests);

    void generation_des_preuves(double l, vector<NTL::ZZX> gamma, vector<Ptxt<BGV>> messages_tests, vector<random_chiffrement> randoms_tests, vector<Ptxt<BGV>> messages_preuves, vector<random_chiffrement> randoms_preuves);


};