#include <iostream>
#include <fstream>
#include <sstream>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <csignal>
#include <algorithm>
#include <iomanip>
#include <ctime>

using namespace std;

// ── Global State ──────────────────────────────
atomic<bool>  running(true);
atomic<int>   packetCount(0), alertCount(0);
atomic<int>   httpCount(0), httpsCount(0), sshCount(0), udpCount(0), icmpCount(0), otherCount(0);

mutex queueMutex, logMutex, trackerMutex;
queue<pair<vector<unsigned char>, int>> packetQueue;
ofstream logFile;

map<string, int>         synTracker;
map<string, int>         icmpTracker;
map<string, vector<int>> portScanTracker;

// ── Helpers ───────────────────────────────────
void handleSignal(int) { running = false; }

string timestamp() {
    time_t now = time(0); tm* t = localtime(&now);
    ostringstream o;
    o << 1900+t->tm_year << "-" << setw(2) << setfill('0') << 1+t->tm_mon
      << "-" << setw(2) << setfill('0') << t->tm_mday << " "
      << setw(2) << setfill('0') << t->tm_hour << ":"
      << setw(2) << setfill('0') << t->tm_min  << ":"
      << setw(2) << setfill('0') << t->tm_sec;
    return o.str();
}

void alert(const string& sev, const string& msg) {
    alertCount++;
    string color = (sev=="CRITICAL") ? "\033[1;31m" : (sev=="HIGH") ? "\033[0;31m" : "\033[0;33m";
    cout << color << "[" << sev << "]\033[0m " << timestamp() << " | " << msg << "\n";
    lock_guard<mutex> lk(logMutex);
    logFile << "{\"level\":\"ALERT\",\"severity\":\"" << sev
            << "\",\"time\":\"" << timestamp()
            << "\",\"msg\":\"" << msg << "\"}\n";
    logFile.flush();
}

void logPacket(const string& proto, const string& src, const string& dst,
               int sp, int dp, int sz, const string& flags) {
    lock_guard<mutex> lk(logMutex);
    logFile << "{\"proto\":\"" << proto << "\",\"src\":\"" << src << ":" << sp
            << "\",\"dst\":\"" << dst << ":" << dp << "\",\"size\":" << sz
            << ",\"flags\":\"" << flags << "\",\"time\":\"" << timestamp() << "\"}\n";
    logFile.flush();
}

// ── TCP ───────────────────────────────────────
void analyzeTCP(unsigned char* buf, int sz, const string& src, const string& dst) {
    auto* ip  = (struct iphdr*)buf;
    auto* tcp = (struct tcphdr*)(buf + ip->ihl * 4);
    int sp = ntohs(tcp->source), dp = ntohs(tcp->dest);

    string flags;
    if (tcp->syn) flags += "SYN ";
    if (tcp->ack) flags += "ACK ";
    if (tcp->fin) flags += "FIN ";
    if (tcp->rst) flags += "RST ";
    if (!flags.empty()) flags.pop_back();

    string proto = "OTHER";
    if      (dp==80  || sp==80)  { proto="HTTP";  httpCount++;  }
    else if (dp==443 || sp==443) { proto="HTTPS"; httpsCount++; }
    else if (dp==22  || sp==22)  { proto="SSH";   sshCount++;   }
    else otherCount++;

    cout << "\033[0;32m[TCP #" << packetCount << "]\033[0m "
         << src << ":" << sp << " -> " << dst << ":" << dp
         << " [" << flags << "] " << proto << " " << sz << "B\n";
    logPacket(proto, src, dst, sp, dp, sz, flags);

    // SYN Flood detection
    if (tcp->syn && !tcp->ack) {
        lock_guard<mutex> lk(trackerMutex);
        if (++synTracker[src] == 20)
            alert("HIGH", "SYN Flood from " + src + " (" + to_string(synTracker[src]) + " SYNs)");
        else if (synTracker[src] > 20 && synTracker[src] % 50 == 0)
            alert("CRITICAL", "SYN Flood ongoing from " + src);
    }

    // Port Scan detection
    {
        lock_guard<mutex> lk(trackerMutex);
        auto& ports = portScanTracker[src];
        if (find(ports.begin(), ports.end(), dp) == ports.end())
            ports.push_back(dp);
        if ((int)ports.size() == 15)
            alert("HIGH", "Port Scan from " + src + " (" + to_string(ports.size()) + " ports)");
        else if ((int)ports.size() > 15 && ports.size() % 20 == 0)
            alert("CRITICAL", "Aggressive Port Scan from " + src);
    }
}

// ── UDP ───────────────────────────────────────
void analyzeUDP(unsigned char* buf, int sz, const string& src, const string& dst) {
    auto* ip  = (struct iphdr*)buf;
    auto* udp = (struct udphdr*)(buf + ip->ihl * 4);
    int sp = ntohs(udp->source), dp = ntohs(udp->dest);
    udpCount++;

    string proto = (dp==53||sp==53) ? "DNS" : (dp==67||sp==67) ? "DHCP" : "UDP";
    cout << "\033[0;34m[UDP #" << packetCount << "]\033[0m "
         << src << ":" << sp << " -> " << dst << ":" << dp
         << " " << proto << " " << sz << "B\n";
    logPacket(proto, src, dst, sp, dp, sz, "");
}

// ── ICMP ──────────────────────────────────────
void analyzeICMP(unsigned char* buf, int sz, const string& src, const string& dst) {
    auto* ip   = (struct iphdr*)buf;
    auto* icmp = (struct icmphdr*)(buf + ip->ihl * 4);
    icmpCount++;

    string type;
    switch(icmp->type) {
        case ICMP_ECHO:         type = "Echo Request"; break;
        case ICMP_ECHOREPLY:    type = "Echo Reply";   break;
        case ICMP_DEST_UNREACH: type = "Unreachable";  break;
        default: type = "Type=" + to_string(icmp->type);
    }

    cout << "\033[0;35m[ICMP #" << packetCount << "]\033[0m "
         << src << " -> " << dst << " [" << type << "] " << sz << "B\n";
    logPacket("ICMP", src, dst, 0, 0, sz, type);

    // ICMP Flood detection
    lock_guard<mutex> lk(trackerMutex);
    if (++icmpTracker[src] == 30)
        alert("MEDIUM", "ICMP Flood from " + src);
    else if (icmpTracker[src] > 30 && icmpTracker[src] % 50 == 0)
        alert("HIGH", "ICMP Flood ongoing from " + src);
}

// ── Analysis Thread ───────────────────────────
void analysisThread() {
    while (running || !packetQueue.empty()) {
        pair<vector<unsigned char>, int> item;
        {
            lock_guard<mutex> lk(queueMutex);
            if (packetQueue.empty()) continue;
            item = packetQueue.front();
            packetQueue.pop();
        }
        unsigned char* buf = item.first.data();
        int sz = item.second;
        auto* ip = (struct iphdr*)buf;
        packetCount++;

        string src = inet_ntoa(*(struct in_addr*)&ip->saddr);
        string dst = inet_ntoa(*(struct in_addr*)&ip->daddr);

        if      (ip->protocol == IPPROTO_TCP)  analyzeTCP(buf, sz, src, dst);
        else if (ip->protocol == IPPROTO_UDP)  analyzeUDP(buf, sz, src, dst);
        else if (ip->protocol == IPPROTO_ICMP) analyzeICMP(buf, sz, src, dst);
        else otherCount++;
    }
}

// ── Capture Thread ────────────────────────────
void captureThread(int sock) {
    unsigned char buf[65536];
    struct sockaddr addr; socklen_t addrLen = sizeof(addr);
    while (running) {
        int sz = recvfrom(sock, buf, sizeof(buf), 0, &addr, &addrLen);
        if (sz < 0) { if (!running) break; continue; }
        lock_guard<mutex> lk(queueMutex);
        packetQueue.push({vector<unsigned char>(buf, buf+sz), sz});
    }
}

// ── Main ──────────────────────────────────────
int main() {
    signal(SIGINT, handleSignal);

    logFile.open("ids_log.json", ios::app);
    if (!logFile.is_open()) { cerr << "Cannot open log file!\n"; return 1; }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) { perror("Socket failed (run as sudo)"); return 1; }

    cout << "\033[1;32m[IDS] Started — Press Ctrl+C to stop\033[0m\n\n";

    thread t1(captureThread, sock);
    thread t2(analysisThread);
    t1.join(); t2.join();

    close(sock);

    cout << "\n\033[1;37m===== SUMMARY =====\033[0m\n"
         << "Total  : " << packetCount << "\n"
         << "HTTP   : " << httpCount   << "\n"
         << "HTTPS  : " << httpsCount  << "\n"
         << "SSH    : " << sshCount    << "\n"
         << "UDP    : " << udpCount    << "\n"
         << "ICMP   : " << icmpCount   << "\n"
         << "Alerts : " << alertCount  << "\n";

    logFile.close();
    return 0;
}