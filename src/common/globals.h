#ifndef ADDRA_GLOBAL_H
#define ADDRA_GLOBAL_H



#include <netinet/in.h>
#include <sys/socket.h>
#include<unistd.h>
#include<strings.h>
#include<string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include<vector>
#include <pthread.h>
#include <cstddef>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <memory>
#include <limits>
#include <sstream> 
#include<cmath>
#include<ctime>
#include<stack>

#include <openssl/aes.h>
#include <rpc/client.h>
#include<rpc/server.h>
#include "seal/seal.h"

#define N 4096
#define PLAIN_BIT 19
#define COEFF_MODULUS_54 18014398509309953UL
#define COEFF_MODULUS_55 36028797018652673UL
#define PLAIN_MODULUS 270337
#define NUM_CT_PER_QUERY (2 * (NUM_MESSAGE / N))
#define SUBROUND_TIME 480 // In miliseconds
#define RAW_DB_SIZE (MESSAGE_SIZE * NUM_MESSAGE)
#define SERVER_PACKET_SIZE (8 * 1024)
#define CLIENT_PACKET_SIZE (64 * 1024)
#define CT_SIZE (2 * 8 * N) //In Bytes
#define OPTIMIZATION_2

#endif