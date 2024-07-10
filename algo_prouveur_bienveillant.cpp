#include <iostream>
#include <helib/helib.h>
#include <random>

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
    unsigned long l = 8;
    vector<long> mvec,gens,ords;

    //Test

    //m = 3*11*(31);p = 17;mvec ={11,3,31};gens = {838,683};ords = {10,2};bits= 700;//20 !

    //m = 9455;p = 17;mvec = {31,5,61};gens = {3661,1892};ords = {30,4}; //40 !

    //m=5*7*11*(61); p=17; mvec={11,7,5,61}; gens={2136,3356,14092}; ords={10,6,4};bits=600; //60 !

    m=7*19*(181); p=17; mvec={19,7,181}; gens={3802,3440,2395}; ords={18,6,5};bits=550; // 80 !

    //m=3*7*(31)*71; p=17; mvec={71,7,3,31}; gens={23437,6604,30815}; ords={70,6,2};bits=600;//92 !

    //m=5*7*(1321); p=17; mvec={7,5,1321}; gens={26421,27742,10571}; ords={6,4,55};bits=700; //100 !!!Pas mal celui là!!!

    //m=5*13*19*(37); p=17; mvec={19,13,5,37}; gens={16836,28121,36557}; ords={18,12,4}; //130


    Context context = ContextBuilder<BGV>()
                                .m(m)
                                .p(p)
                                .r(r)	
                                .gens(gens)
                                .ords(ords)
                                .bits(bits)
                                .c(c)
                                .thinboot()
                                .thickboot()
                                .buildCache(true)
                                .bootstrappable(true)
                                .mvec(mvec)
                                .build();




    // Print the context
    cout << "Début de l'algorithme" << endl;
    //context.printout();

    //On génère les clés
    cout << "Génération des clés ..." << endl;
    SecKey secretKey = SecKey(context);
    secretKey.GenSecKey();
    addSome1DMatrices(secretKey);
    const PubKey& publicKey = secretKey;
    cout << "Clés générées \n" << endl;
    

    // Initialisation de l'espace plaintext
    cout << "Le plaintext m est généré par le prouveur..." << endl;
    helib::Ptxt<helib::BGV> plaintext1(context);
    plaintext1[0] = 2; // Exemple de message à chiffrer
    plaintext1[1] = 4; // Exemple de message à chiffrer
    plaintext1[2] = 3;
    cout << "Le plaintext m est généré.\n" << endl;

    // Génération bienveillante du chiffré de m en stockant r et e
    cout << "On entre dans la Generate-phase..." << endl;
    cout << "Génération de r variable aléatoire ..." << endl;
    DoubleCRT r_random_r(context, context.getCtxtPrimes());   
    double r_bound_r = r_random_r.sampleSmallBounded();
    cout << "Génération de r variable aléatoire terminée" << endl;
    cout << "Chiffrement du plaintext m..." << endl;
    Ctxt cypher(publicKey);
    std::pair<std::vector<NTL::xdouble>,std::vector<DoubleCRT>> e_vecteur_r = publicKey.Encrypt(cypher, plaintext1, r_random_r, r_bound_r);
    std::vector<NTL::xdouble> e_bound_r = e_vecteur_r.first;
    std::vector<DoubleCRT> e_r = e_vecteur_r.second;
    cout << "Chiffrement du plaintext m terminé.\n Envoie de c au vérifieur. \n" << endl;
    cout << "Fin de la Generate-phase \n" << endl;


    //On génère la preuve
    cout << "Début de la Prove-phase...\n" << endl;
    cout << "Génération de l messages u_i aléatoires et de l y_i variables aléatoires..." << endl;

    //On initialise toutes les variables
    vector<Ptxt<BGV>> u (l, helib::Ptxt<helib::BGV>(context));
    vector<Ctxt> w (l, Ctxt(publicKey));
    vector<vector<DoubleCRT>> e_y (l, vector<DoubleCRT> (2,DoubleCRT(context, context.getCtxtPrimes())));
    vector<DoubleCRT> r_y (l, DoubleCRT(context, context.getCtxtPrimes()));
    vector<double> r_bound_y (l);
    vector<vector<NTL::xdouble>> e_bound_y (l);
    pair<vector<NTL::xdouble>,vector<DoubleCRT>> vecteur;

    cout << "On a initialisé" << endl;
    for (long i = 0; i < l; ++i){
        //On veut générer un plaintext aléatoire
        helib::Ptxt<helib::BGV> plaintext(context);
        Ctxt cyphertext(publicKey);
        plaintext.random();
        u[i] = plaintext;
        //On veut générer des variables aléatoires et les stocker dans une structure
        DoubleCRT r_random(context, context.getCtxtPrimes());
        double r_bound = r_random.sampleSmallBounded();
        r_y[i] = r_random;
        r_bound_y[i] = r_bound;
        vecteur = publicKey.Encrypt(cyphertext, plaintext, r_random, r_bound);
        e_y[i] = vecteur.second;
        e_bound_y[i] = vecteur.first;
        w[i]=cyphertext;
    }
    cout << "Génération de l messages u_i aléatoires et de l y_i variables aléatoires terminée" << endl;
    cout << "On envoie les chiffrés w_i correspondant aux messages u_i et aux variables aléatoires v_i au vérifieur.\n " << endl;
   
    //Réponse du vérifieur
    cout << "Début de la génération des gamma_i monomes..." << endl;

    // On veut générer les l monomes gamma de type ZZX pour chaque i
    int k; 
    int n = 5;
    vector<NTL::ZZX> gamma(l);
    for (long i = 0; i < l; ++i){
        NTL::ZZX monomial;
        //on veut k aléatoire inférieur à 2*n
        k =  rand() % (2*n);
        monomial.SetLength(k + 1);
        monomial[k] = 1; // X^k
        gamma[i] = monomial;
    }
    cout << "Fin de la génération des gamma_i monomes\n" << endl;

    cout << "Envoi des gamma_i monomes au prouveur\n"   << endl;

    //Réponse du prouveur

    cout << "Construction des v_i et des z_i "  << endl;

    vector<helib::Ptxt<helib::BGV>> v (l, helib::Ptxt<helib::BGV>(context));
    vector<vector<DoubleCRT>> e_z (l, vector<DoubleCRT> (2,DoubleCRT(context, context.getCtxtPrimes())));
    vector<DoubleCRT> r_z (l, DoubleCRT(context, context.getCtxtPrimes()));
    vector<double> r_bound_z (l);
    vector<vector<NTL::xdouble>> e_bound_z (l);

    ZZX m_poly = plaintext1.getPolyRepr();
    for (long i = 0; i < l; ++i){
        // Génération des v_i
        ZZX poly_v_i = gamma[i] * m_poly;
        Ptxt<BGV> v_i(context, poly_v_i);
        v_i += u[i];
        v[i] = v_i;

        // Génération des z_i
        helib::DoubleCRT dcrt(gamma[i], context, context.getCtxtPrimes()); //On convertit gamma_i en DoubleCRT
        e_z[i] = e_r;
        for (size_t j = 0; j < e_r.size(); ++j) {
            e_z[i][j] *= dcrt;
            e_z[i][j] += e_y[i][j];
        }
        r_z[i] = r_random_r;
        r_z[i] *= dcrt;
        r_z[i] += r_y[i];
        r_bound_z[i] = r_bound_y[i] + r_bound_r;
        //cout << "Ca coince en e_bound akha" << endl;
        vector<NTL::xdouble> e_bound_par (e_bound_y[i].size());
        for (size_t j = 0; j < e_bound_y[i].size(); ++j) {
            e_bound_par[j]=(e_bound_y[i][j] + e_bound_r[j]);
        }
        e_bound_z[i] = e_bound_par;
    }
    cout << "Fin de la construction des v_i et des z_i\n" << endl;
    cout << "Envoi des v_i et des z_i au vérifieur\n" << endl;
    cout << "Début de la vérification des égalités\n" << endl;

    //Vérification des égalités
    helib::Ctxt result(publicKey);
    for (long i = 0; i < l; ++i){
        helib::DoubleCRT dcrt(gamma[i], context, context.getCtxtPrimes()); //On convertit gamma_i en DoubleCRT
        publicKey.Encrypt(result, v[i], r_z[i], e_z[i], e_bound_z[i], r_bound_z[i]);
        Ctxt somme(publicKey);
        somme = cypher;
        somme.parts[1] *= dcrt;
        somme += w[i];
        cout << "Vérification de l'égalité " << i << "..." << endl; 
        if (result.parts[1] != somme.parts[1] && (r_z) ){
            cout << "La vérification n'a pas fonctionné" << endl;
            return 0;
        }
    }
    cout << "La vérification a fonctionné\n" << endl;
    cout << "Fin de la Prove-phase\n" << endl;
    cout << "Fin de l'algorithme\n" << endl;
    cout << "Le prouveur est honnête" << endl;

}


//vector<Ctxt> generate_vecteur_ctxt(){};
// Commande d'éxecution : g++ -std=c++17 -I/usr/local/helib_pack/include/ algo.cpp -o algo -L/usr/local/helib_pack/lib -L/usr/local/lib -lhelib -lntl