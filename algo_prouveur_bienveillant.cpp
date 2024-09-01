#include <iostream>
#include <helib/helib.h>
#include <random>
#include <chrono>

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
    unsigned long l = 20;
    unsigned long n = 30;
    vector<long> mvec,gens,ords;

    //Testés

    //m = 3*11*(31);p = 17;mvec ={11,3,31};gens = {838,683};ords = {10,2};bits= 100;//100 !

    //m = 9455;p = 17;mvec = {31,5,61};gens = {3661,1892};ords = {30,4};bits=100; //100 !

    //m=7*19*(181); p=17; mvec={19,7,181}; gens={3802,3440,2395}; ords={18,6,5};bits=100; // 100 !

    //m=7*19*37; p=17; mvec={19,7,37}; gens={388,402,210}; ords={18,6,36}; bits=100;

    //m=5*23*47; p=17; mvec={23,5,47}; gens={106,115,345}; ords={22,4,46}; bits=100;

    //m=11*31*41; p=17; mvec={31,11,41}; gens={330,352,410}; ords={30,10,40}; bits=100;

    m=13*37*43; p=17; mvec={37,13,43}; gens={370,481,560}; ords={36,12,42}; bits=100;

    //m=19*41*43; p=17; mvec={41,19,43}; gens={410,517,690}; ords={40,16,42}; bits=100;


    

    // Ne marche pas :

    //m=5*7*11*(61); p=17; mvec={11,7,5,61}; gens={2136,3356,14092}; ords={10,6,4};bits=600; //60 !!!!!!!

    //m=3*7*(31)*71; p=17; mvec={71,7,3,31}; gens={23437,6604,30815}; ords={70,6,2};bits=600;//92 !!!!!!

    //m=5*7*(1321); p=17; mvec={7,5,1321}; gens={26421,27742,10571}; ords={6,4,55};bits=700; //100 !!!Pas mal celui là!!!

    //m=5*13*19*(37); p=17; mvec={19,13,5,37}; gens={16836,28121,36557}; ords={18,12,4}; //130


    // m = 129; p = 7; 


    Context context = ContextBuilder<BGV>()
                                .m(m)
                               .p(p)
                               .r(r)	
                               /*.gens(gens)
                               .ords(ords)*/
                               //.bits(bits)
                               .c(c)
                               /*.thinboot()
                               .thickboot()
                               .buildCache(true)
                               .bootstrappable(true)
                               .mvec(mvec)*/
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

    double temps_total; // Variable pour stocker le temps total d'exécution de l'algorithme
    
    std::ofstream myfile;

    myfile.open ("Performace.txt", std::ios_base::app);

    myfile << "\n Paramètres : n = "<< n  << ", l : " << l << ", p :" << p << ", m :" << m << std::endl;

    // On itère sur un nombre d'instances n du problème 

    for (long compteur = 0; compteur < n; ++compteur){

        auto start = std::chrono::high_resolution_clock::now();

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
            Ptxt<BGV> v_i(context);
            v_i = plaintext1;
            m_poly = v_i.getPolyRepr();
            m_poly *= gamma[i];
            v_i.decodeSetData(m_poly);
            v_i += u[i];
            v[i] = v_i;

            // Génération des z_i

            e_z[i] = e_r;
            for (size_t j = 0; j < e_r.size(); ++j) {
                e_z[i][j] *= gamma[i];
                e_z[i][j] += e_y[i][j];
            }
            r_z[i] = r_random_r;
            r_z[i] *= gamma[i];
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
        for (long j = 0; j < l; ++j){
            publicKey.Encrypt(result, v[j], r_z[j], e_z[j], e_bound_z[j], r_bound_z[j]);
            Ctxt somme(publicKey);
            somme = cypher;
            cout << "gamma :" << gamma[j] << endl; 
            somme.parts[0] *= gamma[j];
            somme.parts[1] *= gamma[j];
            somme += w[j];

            DoubleCRT poly1 = result.parts[0];
            DoubleCRT poly2 = somme.parts[0];
            ZZX poly_test1;
            ZZX poly_test2;
            poly1.toPoly(poly_test1);
            poly2.toPoly(poly_test2);

            for (auto i = 0; i < deg(poly_test1)+1; ++i) {
                if (poly_test1[i] + p == poly_test2[i])
                {
                    poly_test1[i] += p;
                }
                else if (poly_test1[i] == poly_test2[i] + p)
                {
                    poly_test1[i] -= p;
                }
                else if (poly_test1[i] == poly_test2[i] + 2*p)
                {
                    poly_test1[i] -= 2*p;
                }
                else if (poly_test1[i] + 2*p  == poly_test2[i])
                {
                    poly_test1[i] += 2*p;
                }
                else if (poly_test1[i] == poly_test2[i] + 3*p)
                {
                    poly_test1[i] -= 3*p;
                }
                else if (poly_test1[i] + 3*p  == poly_test2[i])
                {
                    poly_test1[i] += 3*p;
                }
                else if (poly_test1[i] == poly_test2[i] + 4*p)
                {
                    poly_test1[i] -= 4*p;
                }
                else if (poly_test1[i] + 4*p  == poly_test2[i])
                {
                    poly_test1[i] += 4*p;
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
                return 0;
            }

            cout << "Le resulat est bon" << endl;
        }
        cout << "La vérification a fonctionné\n" << endl;
        cout << "Fin de la Prove-phase\n" << endl;
        cout << "Fin de l'algorithme\n" << endl;
        cout << "Le prouveur est honnête" << endl;

         // Fin de la mesure du temps
        auto end = std::chrono::high_resolution_clock::now();
    
        // Calculer la durée
        std::chrono::duration<double> duration = end - start;

        temps_total  += duration.count();
        
        // Afficher la durée dans un fichier de sortie .txt en sautant une ligne 

        myfile << "Temps d'exécution de l'algorithme "<< compteur << ": " << duration.count() << "s " << std::endl;
    }

    myfile << "\n Temps d'exécution moyen de l'algorithme : " << temps_total/n << "s " << std::endl;

    myfile.close();
}


//vector<Ctxt> generate_vecteur_ctxt(){};
// Commande d'éxecution : g++ -std=c++17 -I/usr/local/helib_pack/include/ algo.cpp -o algo -L/usr/local/helib_pack/lib -L/usr/local/lib -lhelib -lntl