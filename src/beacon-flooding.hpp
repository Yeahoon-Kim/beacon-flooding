#pragma once

#include "802-11.hpp"
#include <pcap.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <vector>

class beaconFlood {
private: 
    std::vector<std::string> SSIDList;
    uint32_t interval;
    uint32_t sendInterval;
    uint8_t channel;
    Mac startMac;

    std::string dev;
public:
    beaconFlood() = default;
    beaconFlood(const std::string& msgFile,std::string dev);

    ~beaconFlood() = default;

    void init(beaconFrame& packet);
    void run();
};

struct beaconFrame {
    radiotap radioHdr;
    beaconHeader beaconHdr;
    uint8_t dummy[256];
    size_t size;
};
