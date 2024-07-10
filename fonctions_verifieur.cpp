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

bool verification(Context context, vector<Ptxt<BGV>> v, vector<vector<DoubleCRT>> e_z, vector<DoubleCRT> r_z, vector<double> r_bound_z, vector<vector<NTL::xdouble>> e_bound_z, Ctxt c, vector<Ctxt> w, const PubKey& publicKey){
    helib::Ctxt result(publicKey);
    Ctxt somme(publicKey);
    for (long i = 0; i < v.size(); ++i){
        helib::DoubleCRT dcrt(gamma[i], context, context.getCtxtPrimes()); //On convertit gamma_i en DoubleCRT
        publicKey.Encrypt(result, v[i], r_z[i], e_z[i], e_bound_z[i], r_bound_z[i]);
        somme = c;
        somme.parts[1] *= dcrt;
        somme += w[i];
        cout << "Vérification de l'égalité " << i << "..." << endl; 
        if (result.parts[1] != somme.parts[1]){
            cout << "La vérification n'a pas fonctionné" << endl;
            return false;
        }
    }
    return true;
}