#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <vector>
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
#include <cmath>
#include <ctime>
#include <stack>
#include <rpc/server.h>
#include <iostream>
#include "seal/seal.h"
#include <globals.h>

using namespace std;
using namespace seal;

#define MASTER_PORT 3000
#define SERVER_PORT 4000

string MASTER_PUBLIC_IP = "";
string MASTER_PRIVATE_IP = "";

int MESSAGE_SIZE;
int NUM_MESSAGE;
int NUM_CLIENT = 1;
int NUM_ROUND = 1;
int NUM_WORKER = 0;

int msg_count = 0;

char *raw_db;

uint64_t *db_send_timestamp;
uint64_t **msg_rcv_timestamp;

int current_round = 0;

pthread_mutex_t db_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t db_cond = PTHREAD_COND_INITIALIZER;

pthread_mutex_t msg_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t msg_cond = PTHREAD_COND_INITIALIZER;

bool all_msg_received = false;


Ciphertext **query;
GaloisKeys *gal_keys;
BatchEncoder *batch_encoder;

seal::parms_id_type pid;

clock_t total_cpu_start_time, total_cpu_stop_time;

void sendMSG(int id, string msg);
string sendDB(int round);
void printReport();

int main(int argc, char *argv[])
{

    int option;
    const char *optstring = "s:m:r:a:w:p:l:";
    while ((option = getopt(argc, argv, optstring)) != -1)
    {
        switch (option)
        {
        case 's':
            MESSAGE_SIZE = stoi(optarg);
            break;
        case 'm':
            NUM_MESSAGE = stoi(optarg);
            break;
        case 'r':
            NUM_ROUND = stoi(optarg);
            break;
        case 'a':
            NUM_CLIENT = stoi(optarg);
            break;
        case 'w':
            NUM_WORKER = stoi(optarg);
            break;
        case 'l':
            MASTER_PRIVATE_IP = string(optarg);
            break;
        case 'p':
            MASTER_PUBLIC_IP = string(optarg);
            break;

        case '?':
            cout << "error optopt: " << optopt << endl;
            cout << "error opterr: " << opterr << endl;
            return 1;
        }
    }
    if (!MESSAGE_SIZE)
    {
        cout << "Missing -s\n";
        return 0;
    }
    if (!NUM_MESSAGE)
    {
        cout << "Missing -m\n";
        return 0;
    }
    if (!NUM_WORKER)
    {
        cout << "Missing -w\n";
        return 0;
    }

    if(MASTER_PUBLIC_IP.size() < 7) {cout<<"Missing -p\n";return 0;}
    if(MASTER_PRIVATE_IP.size() < 7) {cout<<"Missing -l\n";return 0;}

    raw_db = new char[RAW_DB_SIZE];
    for (int i = 0; i < RAW_DB_SIZE; i++)
    {
        raw_db[i] = 100 + i & 127;
    }
    db_send_timestamp = new uint64_t[NUM_ROUND];

    msg_rcv_timestamp = new uint64_t *[NUM_CLIENT];
    for (int i = 0; i < NUM_CLIENT; i++)
    {
        msg_rcv_timestamp[i] = new uint64_t[NUM_ROUND];
    }

    chrono::high_resolution_clock::time_point time_start, time_end, total_start, total_end;
    srand(time(NULL));

    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(N);

    parms.set_coeff_modulus({COEFF_MODULUS_54, COEFF_MODULUS_55});
    parms.set_plain_modulus(PLAIN_MODULUS);

    auto context = SEALContext::Create(parms);

    //pthread_create(&db_thread, NULL, RunDBServer, NULL);

    rpc::server *db_server[NUM_WORKER];
    for (int i = 0; i < NUM_WORKER; i++)
    {
        db_server[i] = new rpc::server(MASTER_PRIVATE_IP, MASTER_PORT + i);
        db_server[i]->bind("sendDB", sendDB);
        db_server[i]->async_run(1);
    }

    rpc::server msg_server(MASTER_PUBLIC_IP, SERVER_PORT);
    msg_server.bind("sendMSG", sendMSG);
    msg_server.async_run(1);
    //pthread_create(&msg_thread, NULL, RunMSGServer, NULL);
    total_cpu_start_time = clock();

    while (current_round < NUM_ROUND)
    {
        //cout<<"Starting round "<<current_round+1<<endl;
        pthread_mutex_lock(&msg_lock);
        while (!all_msg_received)
        {
            pthread_cond_wait(&msg_cond, &msg_lock);
        }
        pthread_mutex_unlock(&msg_lock);

        pthread_mutex_lock(&db_lock);
        for (int i = 0; i < RAW_DB_SIZE; i++)
        {
            //raw_db[i] =  rand() % 128;
            // Replacing rand() with a variable function for faster population
            raw_db[i] = 100 + current_round * 5 + (i & 127); 
        }
        //cout<<"complete initializing DB\n";
        current_round++;
        pthread_cond_broadcast(&db_cond);
        pthread_mutex_unlock(&db_lock);
        all_msg_received = false;
        //cout<<"Finished round "<<current_round<<endl;
    }
    std::this_thread::sleep_for(std::chrono::seconds(5));
    total_cpu_stop_time = clock();

    printReport();

    return 0;
}

void sendMSG(int id, string msg)
{
    auto time_stamp = chrono::high_resolution_clock::now();
    msg_rcv_timestamp[id][current_round] = chrono::duration_cast<chrono::microseconds>(time_stamp.time_since_epoch()).count();
    memcpy(raw_db + id * MESSAGE_SIZE, msg.c_str(), MESSAGE_SIZE);
    pthread_mutex_lock(&msg_lock);
    msg_count++;
    if (msg_count == NUM_CLIENT)
    {
        all_msg_received = true;
        msg_count = 0;
        pthread_cond_broadcast(&msg_cond);
    }

    pthread_mutex_unlock(&msg_lock);
}

string sendDB(int round)
{
    //cout<<"Received DB request for round "<<round<<endl;
    if (round == -1)
        return (string(raw_db)); //Warm up
    while (current_round < round)
    {
        pthread_mutex_lock(&db_lock);
        pthread_cond_wait(&db_cond, &db_lock);
        pthread_mutex_unlock(&db_lock);
    }
    auto time_stamp = chrono::high_resolution_clock::now();
    //cout << "Start DB send: " << chrono::duration_cast<chrono::microseconds>(time_stamp.time_since_epoch()).count() << endl;
    //db_send_timestamp[current_round-1] = chrono::duration_cast<chrono::microseconds>(time_stamp.time_since_epoch()).count();
    return (string(raw_db));
}

void printReport()
{
    cout << "Total CPU time including warm up:(sec)\n"
         << ((float)total_cpu_stop_time - total_cpu_start_time) / CLOCKS_PER_SEC;
    // cout << "\nMessage receive timestamps\n";
    // for (int i = 0; i < NUM_CLIENT; i++)
    // {
    //     for (int j = 0; j < NUM_ROUND; j++)
    //     {
    //         cout << msg_rcv_timestamp[i][j] << '\t';
    //     }
    //     cout << endl;
    // }

    
    // cout<<"\nDB send start timestamps\n\n";
    // for(int i = 0;i<NUM_ROUND;i++) {
    //     cout<<(db_send_timestamp[i]%10000000)/1000<<endl;
    // }

    return;
}