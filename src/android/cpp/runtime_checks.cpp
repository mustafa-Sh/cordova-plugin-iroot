#include "runtime_checks.h"
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <limits.h>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {
struct EncodedValue { const unsigned char* data; std::size_t length; unsigned char key; };

std::string decodeValue(const EncodedValue& v) {
    std::string r(v.length, '\0');
    for (std::size_t i=0;i<v.length;++i) r[i]=static_cast<char>(v.data[i]^v.key);
    return r;
}
void clearValue(std::string& v) {
    if (!v.empty()) {
        volatile char* p=reinterpret_cast<volatile char*>(&v[0]);
        for (std::size_t i=0;i<v.size();++i) p[i]='\0';
    }
    v.clear();
}

// Runtime inspection values.
static const unsigned char V01[] = {0x35, 0x21, 0x3A, 0x37, 0x32};
static const unsigned char V02[] = {0x32, 0x26, 0x3D, 0x30, 0x35, 0x79, 0x33, 0x35, 0x30, 0x33, 0x31, 0x20};
static const unsigned char V03[] = {0x0E, 0x0B, 0x00, 0x04, 0x10, 0x0B, 0x06, 0x03};
static const unsigned char V04[] = {0x23, 0x31, 0x29, 0x69, 0x2E, 0x37, 0x69, 0x28, 0x2B, 0x2B, 0x34};
static const unsigned char V05[] = {0x22, 0x36, 0x2D, 0x20, 0x25, 0x69, 0x25, 0x23, 0x21, 0x2A, 0x30};
static const unsigned char V06[] = {0x28, 0x2D, 0x2A, 0x2E, 0x21, 0x27, 0x30, 0x2B, 0x36};
static const unsigned char V07[] = {0x34, 0x3C, 0x34, 0x3F, 0x3D, 0x63, 0x3F, 0x2B, 0x30, 0x3D, 0x38};
static const unsigned char V08[] = {0x00, 0x17, 0x5C, 0x14, 0x00, 0x1B, 0x16, 0x13};
static const unsigned char V09[] = {0x24, 0x3B, 0x3B, 0x38, 0x79, 0x32, 0x26, 0x3D, 0x30, 0x35};
static const unsigned char P01[] = {0x7A, 0x31, 0x34, 0x21, 0x34, 0x7A, 0x39, 0x3A, 0x36, 0x34, 0x39, 0x7A, 0x21, 0x38, 0x25, 0x7A, 0x33, 0x27, 0x3C, 0x31, 0x34, 0x78, 0x26, 0x30, 0x27, 0x23, 0x30, 0x27};
static const unsigned char P02[] = {0x6B, 0x20, 0x25, 0x30, 0x25, 0x6B, 0x28, 0x2B, 0x27, 0x25, 0x28, 0x6B, 0x30, 0x29, 0x34, 0x6B, 0x36, 0x21, 0x6A, 0x22, 0x36, 0x2D, 0x20, 0x25, 0x6A, 0x37, 0x21, 0x36, 0x32, 0x21, 0x36};
static const unsigned char P03[] = {0x60, 0x3C, 0x36, 0x3C, 0x3B, 0x2A, 0x22, 0x60, 0x2D, 0x26, 0x21, 0x60, 0x29, 0x3D, 0x26, 0x2B, 0x2E, 0x62, 0x3C, 0x2A, 0x3D, 0x39, 0x2A, 0x3D};
static const unsigned char P04[] = {0x0F, 0x53, 0x59, 0x53, 0x54, 0x45, 0x4D, 0x0F, 0x58, 0x42, 0x49, 0x4E, 0x0F, 0x46, 0x52, 0x49, 0x44, 0x41, 0x0D, 0x53, 0x45, 0x52, 0x56, 0x45, 0x52};

static const EncodedValue MAP_VALUES[]={{V01,sizeof(V01),0x53},{V02,sizeof(V02),0x54},{V03,sizeof(V03),0x62},{V04,sizeof(V04),0x44},{V05,sizeof(V05),0x44},{V06,sizeof(V06),0x44},{V07,sizeof(V07),0x59},{V08,sizeof(V08),0x72}};
static const EncodedValue THREAD_VALUES[]={{V01,sizeof(V01),0x53},{V04,sizeof(V04),0x44},{V09,sizeof(V09),0x54},{V06,sizeof(V06),0x44}};
static const EncodedValue FD_VALUES[]={{V01,sizeof(V01),0x53},{V04,sizeof(V04),0x44},{V02,sizeof(V02),0x54},{V03,sizeof(V03),0x62},{V06,sizeof(V06),0x44},{V07,sizeof(V07),0x59},{V08,sizeof(V08),0x72}};
static const EncodedValue ARTIFACT_VALUES[]={{P01,sizeof(P01),0x55},{P02,sizeof(P02),0x44},{P03,sizeof(P03),0x4F},{P04,sizeof(P04),0x20}};

std::string toLower(std::string v) {
    std::transform(v.begin(),v.end(),v.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
    return v;
}
bool containsAnyProtected(const std::string& value,const EncodedValue* values,std::size_t count) {
    if(value.empty()) return false;
    const std::string lower=toLower(value);
    for(std::size_t i=0;i<count;++i) {
        std::string d=decodeValue(values[i]);
        const bool matched=lower.find(d)!=std::string::npos;
        clearValue(d);
        if(matched) return true;
    }
    return false;
}
bool fileExists(const char* path){struct stat info{};return stat(path,&info)==0;}
bool readFirstLine(const std::string& path,std::string& result){std::ifstream f(path);return f.is_open()&&static_cast<bool>(std::getline(f,result));}

bool checkProcMaps(){
    std::ifstream f("/proc/self/maps"); if(!f.is_open()) return false; std::string line;
    while(std::getline(f,line)) if(containsAnyProtected(line,MAP_VALUES,sizeof(MAP_VALUES)/sizeof(MAP_VALUES[0]))) return true;
    return false;
}
bool checkTracerPid(){
    std::ifstream f("/proc/self/status"); if(!f.is_open()) return false; std::string line;
    while(std::getline(f,line)){
        if(line.rfind("TracerPid:",0)!=0) continue;
        std::string v=line.substr(std::strlen("TracerPid:"));
        v.erase(std::remove_if(v.begin(),v.end(),[](unsigned char c){return std::isspace(c);}),v.end());
        if(v.empty()) return false; return v!="0";
    } return false;
}
bool checkThreads(){
    const char* base="/proc/self/task"; DIR* dir=opendir(base); if(!dir) return false; bool detected=false; struct dirent* e;
    while((e=readdir(dir))!=nullptr){
        if(e->d_name[0]=='.') continue; bool numeric=true;
        for(const char* p=e->d_name;*p;++p) if(!std::isdigit(static_cast<unsigned char>(*p))){numeric=false;break;}
        if(!numeric) continue;
        std::string path=std::string(base)+"/"+e->d_name+"/comm", name;
        if(!readFirstLine(path,name)) continue;
        if(containsAnyProtected(name,THREAD_VALUES,sizeof(THREAD_VALUES)/sizeof(THREAD_VALUES[0]))){detected=true;break;}
    } closedir(dir); return detected;
}
bool checkFileDescriptors(){
    const char* base="/proc/self/fd"; DIR* dir=opendir(base); if(!dir) return false; bool detected=false; struct dirent* e;
    while((e=readdir(dir))!=nullptr){
        if(e->d_name[0]=='.') continue;
        std::string link=std::string(base)+"/"+e->d_name; char target[PATH_MAX];
        ssize_t len=readlink(link.c_str(),target,sizeof(target)-1); if(len<=0) continue; target[len]='\0';
        if(containsAnyProtected(std::string(target),FD_VALUES,sizeof(FD_VALUES)/sizeof(FD_VALUES[0]))){detected=true;break;}
    } closedir(dir); return detected;
}
bool checkKnownArtifacts(){
    for(std::size_t i=0;i<sizeof(ARTIFACT_VALUES)/sizeof(ARTIFACT_VALUES[0]);++i){
        std::string p=decodeValue(ARTIFACT_VALUES[i]); bool exists=fileExists(p.c_str()); clearValue(p); if(exists) return true;
    } return false;
}

static volatile std::uint16_t PORT_MASK=0x5A3C;
static const std::uint16_t PORT_VALUES[]={0x339E,0x339F};
std::uint16_t decodePort(std::uint16_t e){const std::uint16_t m=PORT_MASK;return static_cast<std::uint16_t>(e^m);}

bool checkPortFile(const char* path){
    std::ifstream f(path); if(!f.is_open()) return false; std::string line; std::getline(f,line);
    while(std::getline(f,line)){
        std::istringstream s(line); std::string slot,local,remote,state;
        if(!(s>>slot>>local>>remote>>state)) continue; if(state!="0A") continue;
        std::size_t colon=local.find(':'); if(colon==std::string::npos) continue;
        std::string hex=local.substr(colon+1); char* end=nullptr; long port=std::strtol(hex.c_str(),&end,16);
        if(end==hex.c_str()) continue;
        for(std::uint16_t e:PORT_VALUES) if(port==decodePort(e)) return true;
    } return false;
}
bool checkSuspiciousPorts(){return checkPortFile("/proc/net/tcp")||checkPortFile("/proc/net/tcp6");}
}

bool runRuntimeChecks(){
    if(checkProcMaps()) return true;
    if(checkTracerPid()) return true;
    if(checkThreads()) return true;
    if(checkFileDescriptors()) return true;
    if(checkKnownArtifacts()) return true;
    if(checkSuspiciousPorts()) return true;
    return false;
}
