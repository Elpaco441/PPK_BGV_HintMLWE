#include <iostream>
#include <helib/helib.h>
#include <random>
#include "Prouveur.h"
#include "Verifieur.h"
#include "Structure.h"
#include <random>


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

    m = 9455;p = 17;mvec = {31,5,61};gens = {3661,1892};ords = {30,4};bits=100; //100 !

    //m=7*19*(181); p=17; mvec={19,7,181}; gens={3802,3440,2395}; ords={18,6,5};bits=100; // 100 !

    //m=7*19*37; p=17; mvec={19,7,37}; gens={388,402,210}; ords={18,6,36}; bits=100;

    //m=5*23*47; p=17; mvec={23,5,47}; gens={106,115,345}; ords={22,4,46}; bits=100;

    //m=11*31*41; p=17; mvec={31,11,41}; gens={330,352,410}; ords={30,10,40}; bits=100;

    //m=13*37*43; p=17; mvec={37,13,43}; gens={370,481,560}; ords={36,12,42}; bits=100;

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


    // On génère le plaintext m pour la démonstration 


    // Initialisation de l'espace plaintext
    cout << "Le plaintext m est généré par le prouveur..." << endl;
    helib::Ptxt<helib::BGV> message_demo(context);
    message_demo[0] = 2; // Exemple de message à chiffrer
    message_demo[1] = 4; // Exemple de message à chiffrer
    message_demo[2] = 3;
    cout << "Le plaintext m est généré.\n" << endl;

    //On crée le prouveur et le vérifieur

    cout << "Création du prouveur et du vérifieur..." << endl;
    Prouveur prouveur(context,message_demo);

    cout << "Le prouveur est créé.\n" << endl;


    Verifieur verifieur(prouveur.get_pubKey());


    // Génération bienveillante du chiffré de m en stockant r et e
    cout << "On entre dans la Generate-phase..." << endl;
    verifieur.set_ctxt(prouveur.generation_du_chiffre());
    cout << "Fin de la Generate-phase \n" << endl;


    //On génère la preuve
    cout << "Début de la Prove-phase...\n" << endl;
    cout << "Génération de l messages u_i aléatoires et de l y_i variables aléatoires..." << endl;

    //On initialise toutes les variables de test et on les génère grâce à la fonction prouveur 

    vector<Ptxt<BGV>> messages_tests (l, helib::Ptxt<helib::BGV>(context));
    vector<Ctxt> chiffres_tests (l, Ctxt(prouveur.get_pubKey()));
    vector<random_chiffrement> randoms_tests (l,(random_chiffrement(context))); 

    cout << "On a initialisé" << endl;


    double temps_total; // Variable pour stocker le temps total d'exécution de l'algorithme
    
    std::ofstream myfile;

    myfile.open ("Performance.txt", std::ios_base::app);

    myfile << "\n Paramètres : n = "<< n  << ", l : " << l << ", p :" << p << ", m :" << m << std::endl;

    // On itère sur un nombre d'instances n du problème 

    for (long compteur = 0; compteur < n; ++compteur){

        auto start = std::chrono::high_resolution_clock::now();

        
        prouveur.generation_des_tests(l, messages_tests, randoms_tests, chiffres_tests);

    
        //Réponse du vérifieur
        cout << "Début de la génération des gamma_i monomes..." << endl;

        // On veut générer les l monomes gamma de type ZZX pour chaque i   

        int exposant_max = 5;
        vector<NTL::ZZX> gamma(l);
        
        verifieur.genere_monomes(gamma, exposant_max);

        cout << "Fin de la génération des gamma_i monomes\n" << endl;

        cout << "Envoi des gamma_i monomes au prouveur\n"   << endl;



        //Réponse du prouveur

        cout << "Construction du test pour le prouveur "  << endl;

        vector<Ptxt<BGV>> messages_preuves (l, helib::Ptxt<helib::BGV>(context));
        vector<random_chiffrement> randoms_preuves (l,(random_chiffrement(context))); 

        prouveur.generation_des_preuves(l, gamma, messages_tests, randoms_tests, messages_preuves, randoms_preuves);
        
        cout << "Début de la vérification des égalités\n" << endl;

        //Vérification des égalités
        verifieur.verification(l,gamma, messages_preuves, randoms_preuves, chiffres_tests);
    

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