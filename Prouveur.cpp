#include <iostream>
#include <helib/helib.h>
#include <random>
#include "Prouveur.h"
#include "Structure.h"



//On veut employer les méthodes de la bibliothèque helib 
using namespace helib;
using namespace std;
using namespace NTL;


Prouveur::Prouveur(const Context& contexte, const Ptxt<BGV>& mess)
: context(contexte),
  message(mess),
  secKey(*(new SecKey(context))),
  pubKey(secKey),
  chiffre(*(new Ctxt(pubKey))),
  random(*(new random_chiffrement(context)))
{
    secKey.GenSecKey();
    addSome1DMatrices(secKey);
}

//Setters getters

SecKey& Prouveur::get_secKey() {
    return this->secKey; // Retourne la clé secrète
}

PubKey& Prouveur::get_pubKey() {
    return this->pubKey;  // Retourne la clé publique
}


Ptxt<BGV> Prouveur::get_ptxt(){
    return this->message;
}

void Prouveur::set_ctxt(const Ctxt& c){
    this->chiffre = c;
}

Ctxt Prouveur::get_ctxt(){
    return this->chiffre;
}

void Prouveur::set_random_de_chiffrement(const DoubleCRT r, const double& r_b, const vector<NTL::xdouble>& e_b, const vector<DoubleCRT>& e ){
    random_chiffrement new_random(context);
    new_random.r = r;
    new_random.r_bound = r_b;
    new_random.e_bound = e_b;
    new_random.e = e;
    this->random = new_random; 
}

random_chiffrement Prouveur::get_random_de_chiffrement(){
    return this->random;
}

void Prouveur::ecrire_random_de_chiffrement(){
    cout << "Le r est " << random.r << endl;
    cout << "Les r_bound sont " << random.r_bound << endl;
    cout << "Le e est " << random.e << endl; 
    cout << "Les e_bound sont  " << random.e_bound << endl;
}


Ctxt Prouveur::generation_du_chiffre(){
    cout << "Génération de r variable aléatoire ..." << endl;

    //On génère r aléatoire 
    DoubleCRT r_random_r(context, context.getCtxtPrimes());                                

    //On génère r_bound 
    double r_bound_r = r_random_r.sampleSmallBounded();                                  
 
    cout << "Génération de r variable aléatoire terminée" << endl;

    cout << "Chiffrement du plaintext m..." << endl;

    //On genère le chiffré du plaintext m ainsi que les erreurs e et les erreurs bornées e_bound
    Ctxt cypher(pubKey);
    std::pair<std::vector<NTL::xdouble>,std::vector<DoubleCRT>> e_vecteur_r = pubKey.Encrypt(cypher, message, r_random_r, r_bound_r);

    //On stock les erreurs e et les erreurs bornées e_bound dans l'objet prouveur
    set_random_de_chiffrement(r_random_r,r_bound_r,e_vecteur_r.first,e_vecteur_r.second);        
    set_ctxt(cypher);
    cout << "Chiffrement du plaintext m terminé.\n Envoie de c au vérifieur. \n" << endl;
    return cypher;
}

    
void Prouveur::generation_des_tests(long l, vector<Ptxt<BGV>> messages_tests, vector<random_chiffrement> randoms_tests, vector<Ctxt> chiffres_tests){

    random_chiffrement random_test(context); 

    for (long i = 0; i < l; ++i){

        //Générer un plaintext aléatoire

        helib::Ptxt<helib::BGV> plaintext(context);
        plaintext.random();
        messages_tests[i] = plaintext;

        //Générer des variables aléatoires et les stocker dans une structure

        DoubleCRT r_random(context, context.getCtxtPrimes());
        random_test.r_bound  = r_random.sampleSmallBounded();
        random_test.r = r_random;

        //Génération du chiffré et stockage dans le vecteur

        Ctxt cyphertext(pubKey);
        std::pair<std::vector<NTL::xdouble>,std::vector<DoubleCRT>> vecteur = pubKey.Encrypt(cyphertext, plaintext, random_test.r, random_test.r_bound);
        chiffres_tests[i]=cyphertext;

        //On récupère les erreurs et on les stocke égalment dans la structure
        
        random_test.e = vecteur.second;
        random_test.e_bound = vecteur.first;

        randoms_tests[i] = random_test;
    }
    cout << "Génération de l messages u_i aléatoires et de l y_i variables aléatoires terminée" << endl;
    cout << "On envoie les chiffrés w_i correspondant aux messages u_i et aux variables aléatoires v_i au vérifieur.\n " << endl;
}


void Prouveur::generation_des_preuves(double l, vector<NTL::ZZX> gamma, vector<Ptxt<BGV>> messages_tests, vector<random_chiffrement> randoms_tests, vector<Ptxt<BGV>> messages_preuves, vector<random_chiffrement> randoms_preuves){

    cout << "Construction des preuves et des randoms "  << endl;


    
    ZZX m_poly = message.getPolyRepr();
    for (long i = 0; i < l; ++i){
        // Génération des v_i
        Ptxt<BGV> message_i(context);
        message_i = message;
        m_poly = message_i.getPolyRepr();
        m_poly *= gamma[i];
        message_i.decodeSetData(m_poly);
        message_i += messages_tests[i];
        messages_preuves[i] = message_i;

        // Génération des z_i

        randoms_preuves[i].e = random.e;
        for (size_t j = 0; j < (random.e).size(); ++j) {
            (randoms_preuves[i].e)[j] *= gamma[i];
            (randoms_preuves[i].e)[j] += (randoms_tests[i].e)[j];
        }
        randoms_preuves[i].r = random.r;
        randoms_preuves[i].r *= gamma[i];
        randoms_preuves[i].r += randoms_tests[i].r;
        randoms_preuves[i].r_bound = randoms_preuves[i].r_bound + random.r_bound;
        
        vector<NTL::xdouble> e_bound_partiel ((randoms_tests[i].e_bound).size());
        for (size_t j = 0; j < (randoms_tests[i].e_bound).size(); ++j) {
            e_bound_partiel[j]=((randoms_tests[i].e_bound)[j] + random.e_bound[j]);
        }
        randoms_preuves[i].e_bound = e_bound_partiel;
    }
    cout << "Fin de la construction des v_i et des z_i\n" << endl;
    cout << "Envoi des v_i et des z_i au vérifieur\n" << endl;

}