# Nom de l'exécutable
TARGET = main

# Compilateur et standard C++
CXX = g++
CXXFLAGS = -std=c++17

# Répertoires d'inclusion
INCLUDES = -I/usr/local/helib_pack/include/

# Fichiers source (notez qu'il n'y a pas de Structure.cpp)
SRCS = main.cpp Prouveur.cpp Verifieur.cpp  # Pas de Structure.cpp ici

# Génère une liste des fichiers objets correspondants
OBJS = $(SRCS:.cpp=.o)

# Répertoires de bibliothèques
LDFLAGS = -L/usr/local/helib_pack/lib -L/usr/local/lib

# Bibliothèques à lier
LIBS = -lhelib -lntl

# Commande finale pour créer l'exécutable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $(TARGET) $(OBJS) $(LDFLAGS) $(LIBS)

# Règle pour compiler les fichiers .cpp en .o
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Règle pour nettoyer les fichiers générés
clean:
	rm -f $(TARGET) $(OBJS)

# Définir des règles phony pour éviter les conflits avec des fichiers du même nom
.PHONY: clean
