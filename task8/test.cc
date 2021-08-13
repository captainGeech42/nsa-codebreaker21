// #include <ctime>
#include <iostream>
#include <sys/utsname.h>
#include <time.h>
#include <sys/time.h>

int main(int argc, char **argv) {
    struct timeval tv;
    gettimeofday(&tv, 0);
    std::cout << tv.tv_sec << std::endl;

    // std::cout << t << std::endl;

    // struct utsname os;
    // uname(&os);

    // std::cout << std::string(os.sysname) << std::endl;
}