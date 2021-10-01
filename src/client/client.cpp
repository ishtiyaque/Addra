#include<globals.h>

using namespace std;
using namespace seal;


#define MASTER_PORT 4000
#define WORKER_PORT 2199
#define CLIENT_PORT 2000

Ciphertext *query;
Ciphertext *result;
GaloisKeys gal_keys;
BatchEncoder *batch_encoder;

Evaluator *evaluator;

Encryptor *encryptor;
Decryptor *decryptor;

seal::parms_id_type pid;
std::shared_ptr<seal::SEALContext> context;
KeyGenerator *keygen;
SecretKey secret_key;

uint64_t **send_timestamp;
uint64_t **recv_timestamp;

int MESSAGE_SIZE;
int NUM_MESSAGE;
int NUM_CLIENT = 1;
int NUM_ROUND = 1;

string MASTER_IP = "";
string CLIENT_IP = "";

char response[CT_SIZE];

pthread_mutex_t start_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t start_cond = PTHREAD_COND_INITIALIZER;

bool start_send = false;

int warm_up_count = 0;

clock_t total_cpu_start_time, total_cpu_stop_time;
clock_t query_gen_cpu_start, query_gen_cpu_stop;

chrono::high_resolution_clock::time_point latency_time_start, latency_time_end;

vector<uint64_t> rotate_plain(vector<uint64_t> original, int index);
void printReport();
void * periodic_send(void *client);

class AddraClient {
public:
    int id;
    int idx; // For local use only
    unsigned char *subround_send_data;
    unsigned char *subround_recv_data;

    int recv_count;
    bool warm_up = false;
    int query_index;
    Plaintext pt; 

    vector<uint64_t> pod_matrix;
    Ciphertext result;
	AES_KEY enc_key, dec_key;
    unsigned char iv[AES_BLOCK_SIZE];



    AddraClient() {
        subround_send_data = new unsigned char[MESSAGE_SIZE];
        subround_recv_data = new unsigned char[MESSAGE_SIZE];
        recv_count=0;   
        query_index = rand()%NUM_MESSAGE; 
        pt.reserve(N);  
        result.reserve(2); 
        pod_matrix = vector<uint64_t>(N, 0ULL);
        encryptor->encrypt_symmetric(pt, result);
        unsigned char aes_key[]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	    AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, &enc_key);
	    AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key); // Size of key is in bits


    }
    AddraClient(int i) {
        idx = i;
        subround_send_data = new unsigned char[MESSAGE_SIZE];
        subround_recv_data = new unsigned char[MESSAGE_SIZE];
        recv_count=0;   
        query_index = rand()%NUM_MESSAGE; 
        pt.reserve(N);  
        result.reserve(2); 
        pod_matrix = vector<uint64_t>(N, 0ULL);
        unsigned char aes_key[]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
	    AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, &enc_key);
	    AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key); // Size of key is in bits


    }
    void sendCT( vector<uint64_t> ct) {
        if(!warm_up) {
            warm_up = true;
            pthread_mutex_lock(&start_lock);  
            warm_up_count++;
            if(warm_up_count == NUM_CLIENT) { 
                //system("sudo cp /proc/net/dev proc_net_dev_pre.txt"); 
                total_cpu_start_time = clock();  
                start_send = true;
                pthread_cond_broadcast(&start_cond);
            }
            pthread_mutex_unlock(&start_lock);

            return;
        }
        auto latency_time_end = chrono::high_resolution_clock::now();
        recv_timestamp[idx][recv_count++] = chrono::duration_cast<chrono::microseconds>(latency_time_end.time_since_epoch()).count();
        assert(ct.size() == (N*2)); 
        std:copy(ct.begin(), ct.end(), result.data());
        decryptor->decrypt(result, pt);
        batch_encoder->decode(pt, pod_matrix);
        pod_matrix = rotate_plain(pod_matrix, 100); // Query index here

        memset(iv, 0x00, AES_BLOCK_SIZE);
	    AES_cbc_encrypt((unsigned char *)subround_send_data, subround_recv_data, MESSAGE_SIZE, &dec_key, iv, AES_DECRYPT); //Placeholder
    
        return;

    }

};

AddraClient *clients;

int main(int argc, char *argv[]) {
    int option;
    const char *optstring = "s:m:r:a:p:c:";
    while ((option = getopt(argc, argv, optstring)) != -1) {
	switch (option) {
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
        case 'p':
            MASTER_IP = string(optarg);
            break;
        case 'c':
            CLIENT_IP = string(optarg);
            break;

        case '?':
            cout<<"error optopt: "<<optopt<<endl;
            cout<<"error opterr: "<<opterr<<endl;
            return 1;
	    }
    }


    if(!MESSAGE_SIZE) {cout<<"Missing -s\n";return 0;}
    if(!NUM_MESSAGE) {cout<<"Missing -m\n";return 0;}
    if(MASTER_IP.size() < 7) {cout<<"Missing -p\n";return 0;}
    if(CLIENT_IP.size() < 7) {cout<<"Missing -c\n";return 0;}

    //system("cp /proc/net/dev proc_net_dev_pre.txt"); 
    send_timestamp = new uint64_t*[NUM_CLIENT];
    recv_timestamp = new uint64_t*[NUM_CLIENT];
    for(int i = 0; i < NUM_CLIENT;i++) {
        send_timestamp[i] = new uint64_t[NUM_ROUND];
        recv_timestamp[i] = new uint64_t[NUM_ROUND];
    }

    chrono::high_resolution_clock::time_point time_start, time_end, total_start, total_end;
    srand (time(NULL));
	EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(N);

    parms.set_coeff_modulus({COEFF_MODULUS_54, COEFF_MODULUS_55});    
    parms.set_plain_modulus(PLAIN_MODULUS); 

    context = SEALContext::Create(parms); 

    keygen = new KeyGenerator(context);
    secret_key = keygen->secret_key();
    
    encryptor = new Encryptor(context, secret_key);
    decryptor = new Decryptor(context, secret_key);

    batch_encoder = new BatchEncoder(context);
    size_t row_size = N / 2;

    GaloisKeys gal_keys = keygen->galois_keys_local();
      
    Ciphertext query[NUM_CT_PER_QUERY];

    int index = rand()%NUM_MESSAGE;
    vector<uint64_t> pod_matrix(N, 0ULL);
    Plaintext pt;

    query_gen_cpu_start = clock();
    for(int j = 0; j < NUM_CT_PER_QUERY; j++) {
        if((index/row_size) == j) {
            pod_matrix[index%row_size] = 1;
            pod_matrix[row_size + (index%row_size)] = 1;
        }
        //print_matrix(pod_matrix, row_size);
        batch_encoder->encode(pod_matrix, pt);
        encryptor->encrypt_symmetric(pt, query[j]);
        //evaluator->transform_to_ntt_inplace(query[client_id][j]);
    }
    query_gen_cpu_stop = clock();

    clients = new AddraClient[NUM_CLIENT];
    int client_interval = (NUM_MESSAGE / NUM_CLIENT);
    for(int i =0;i<NUM_CLIENT;i++) {
        clients[i].idx = i;
        clients[i].id = i *client_interval;
    }
    pthread_t client_threads[NUM_CLIENT];
    for(int i = 0;i<NUM_CLIENT;i++) {
        if(pthread_create(&client_threads[i], NULL, periodic_send, (void *)&clients[i])) {
            printf("Error creating Client thread\n");
            exit(1);
        }
    }
    
 
 
    for(int i = 0;i<NUM_CLIENT;i++) {
        pthread_join(client_threads[i], NULL);        
    }
    total_cpu_stop_time = clock();
    sleep(3);
    //system("sudo cp /proc/net/dev proc_net_dev_post.txt"); 
    printReport();

	return 0;
}


vector<uint64_t> rotate_plain(vector<uint64_t> original, int index) {
    int sz = original.size();
    int row_count = sz/2;
 #ifndef OPTIMIZATION_2  
    int column_switch = (index >= row_count);
    index = index % row_count;
 #endif
    vector<uint64_t> result(sz);
    for(int i = 0; i < row_count; i++) {
#ifdef OPTIMIZATION_2
        result[i] = original[(index + i)%row_count];
        result[row_count + i] = original[row_count + ((index + i)%row_count)];
#else
        result[(column_switch * row_count) + i] = original[(index + i)%row_count];
        result[(1 - column_switch)*row_count + i] = original[row_count + ((index + i)%row_count)];
#endif
    }

    return result;
}

void printReport() {
    cout<<"\nlatency(us)\n";
    for(int i = 0;i<NUM_CLIENT;i++) {
        for(int j = 0; j < NUM_ROUND;j++) {
            cout<<recv_timestamp[i][j] - send_timestamp[i][j]<<"\t";
        }
        cout<<endl;
    }
   
    // cout<<"\nmessage send timestamp\n";
    // for(int i = 0;i<NUM_CLIENT;i++) {
    //     for(int j = 0; j < NUM_ROUND;j++) {
    //         cout<<send_timestamp[i][j]<<"\t";
    //     }
    //     cout<<endl;
    // }

    cout<<"Query generation CPU time 1 client: (sec)\n"<<((double)query_gen_cpu_stop - query_gen_cpu_start)/CLOCKS_PER_SEC<<endl;
    cout<<"Total communication CPU time for all active clients: (sec)\n"<<((float)total_cpu_stop_time-total_cpu_start_time)/CLOCKS_PER_SEC<<endl;;


/*
    cout<<"\nresponse receive timestamps\n";
    for(int i = 0; i < NUM_ROUND;i++) {
        cout<<recv_timestamp[i]<<endl;
    }
*/

    return;
}



void * periodic_send(void *client) {

    using clock = std::chrono::high_resolution_clock;
    
    int send_count = 0;
    AddraClient *cl = (AddraClient *)client;
    unsigned char enc_data[MESSAGE_SIZE];
    rpc::client msg_client(MASTER_IP, MASTER_PORT);
    rpc::server ct_server ( string(CLIENT_IP), CLIENT_PORT + cl->idx);
    //printf("client %d listening at port %d\n", cl->id, CLIENT_PORT + cl->idx);
    ct_server.bind("sendCT", [cl](std::vector<uint64_t> ct){ cl->sendCT(ct); });
    ct_server.async_run(1);

    pthread_mutex_lock(&start_lock);
    while (!start_send) {     
        pthread_cond_wait(&start_cond, &start_lock);
    }
    pthread_mutex_unlock(&start_lock);
    auto timeout = clock::now();
    while(send_count < NUM_ROUND) {
        timeout += std::chrono::microseconds(SUBROUND_TIME * 1000);
        std::memset(cl->iv, 0x00, AES_BLOCK_SIZE);
        for(int i = 0;i<MESSAGE_SIZE;i++) {
            cl->subround_send_data[i] = 100 + cl->idx;
        }
        AES_cbc_encrypt(cl->subround_send_data, enc_data, MESSAGE_SIZE, &cl->enc_key, cl->iv, AES_ENCRYPT);
        send_timestamp[cl->idx][send_count++] = chrono::duration_cast<chrono::microseconds>(clock::now().time_since_epoch()).count();
        msg_client.call("sendMSG",cl->idx, string((char *)enc_data));
        std::this_thread::sleep_until(timeout);
    }
    std::this_thread::sleep_for(std::chrono::seconds(5));

    return NULL;

}

