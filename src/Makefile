CXX = g++
CXXFLAGS = -W -Wall -O2
OBJECTS = ./mac.o ./beacon-flooding.o ./main.o
TARGET = ../bin/beacon-flooding
LIBS = -lpcap

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(@) $(^) $(LIBS)

main.o: ./main.cpp
beacon-flooding.o: ./beacon-flooding.cpp
mac.o : ./mac.hpp ./mac.cpp

clean:
	rm -f $(TARGET)
	rm -f *.o

.PHONY: all clean
