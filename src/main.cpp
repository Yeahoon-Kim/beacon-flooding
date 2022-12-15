#include "beacon-flooding.hpp"

using namespace std;

int main(int argc, char* argv[]) {
    if(argc != 3) {
        cerr << "syntax : beacon-flood <interface> <ssid-list-file>\n";
        cerr << "sample : beacon-flood mon0 ssid-list.txt" << endl;

        return 1;
    }

    beaconFlood flooder(argv[2], argv[1]);

    flooder.run();

    return 0;
}