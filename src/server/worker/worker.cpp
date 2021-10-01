#include<globals.h>
#define MIN(a,b) ((a) < (b)) ? (a) : (b)

#define NTT_NUM_THREAD 8

#define MASTER_PORT 3000
#define WORKER_PORT 2199
#define CLIENT_PORT 2000

using namespace std;
using namespace seal;

unsigned int WORKER_ID = -1;

unsigned int NUM_COLUMNS;
int DB_ROWS;
int MESSAGE_SIZE;
int NUM_MESSAGE;
int NUM_CLIENT;
int NUM_ROUND = 1;
int NUM_ACTIVE_CLIENT = 1;
int NUM_THREAD = 0;
int NUM_WORKER = 0;

string MASTER_IP = "";
string CLIENT_IP = "";

int global_start_id;
int global_end_id;
int active_client_interval;
int active_client_this_worker;
int active_client_start;

int current_round = 0;
int preprocessing_round = 0;
int pir_round = 0;


Ciphertext **query;
Ciphertext *result;
GaloisKeys *gal_keys;
Plaintext *encoded_db;
BatchEncoder *batch_encoder;

Evaluator *evaluator;

Encryptor *encryptor;

seal::parms_id_type pid;
std::shared_ptr<seal::SEALContext> context;
KeyGenerator *keygen;
SecretKey secret_key;

int *thread_id;
int ntt_thread_id[NTT_NUM_THREAD];

pthread_t *threads;
pthread_t ntt_threads[NTT_NUM_THREAD];
pthread_barrier_t preprocess_barrier;
pthread_barrier_t pir_barrier;
pthread_mutex_t preprocess_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t preprocess_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t pir_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t pir_cond = PTHREAD_COND_INITIALIZER;

char *raw_db;

uint64_t *preprocessing_time;
uint64_t *generation_time;

uint64_t *db_recv_timestamp;
uint64_t *response_send_timestamp;

rpc::client **active_clients;

clock_t cpu_start_time, cpu_stop_time;
clock_t total_cpu_start_time, total_cpu_stop_time;
clock_t preprocessing_cpu_time = 0;
clock_t reply_cpu_time = 0;

void printReport();
// void populate_galois_keys();
//void populate_queries();
void *gen_keys(void *thread_id);
void *pir(void *thread_id);
void *preprocess_db(void *thread_id);

int main(int argc, char *argv[]) {

    int option;
    const char *optstring = "i:s:m:r:a:l:w:c:t:";
    while ((option = getopt(argc, argv, optstring)) != -1) {
	switch (option) {
        case 'i':
            WORKER_ID = stoi(optarg);
            break;
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
            NUM_ACTIVE_CLIENT = stoi(optarg);
            break;
        case 'w':
            NUM_WORKER = stoi(optarg);
            break;
        case 't':
            NUM_THREAD = stoi(optarg);
            break;
        case 'l':
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
    if(WORKER_ID == -1) {cout<<"Missing -i\n";return 0;}
    if(!MESSAGE_SIZE) {cout<<"Missing -s\n";return 0;}
    if(!NUM_MESSAGE) {cout<<"Missing -m\n";return 0;}
    if(!NUM_THREAD) {cout<<"Missing -t\n";return 0;}
    if(!NUM_WORKER) {cout<<"Missing -w\n";return 0;}
    if(MASTER_IP.size() < 7) {cout<<"Missing -l\n";return 0;}
    if(CLIENT_IP.size() < 7) {cout<<"Missing -c\n";return 0;}

    NUM_CLIENT = floor((double)NUM_MESSAGE/NUM_WORKER);
    global_start_id = WORKER_ID * NUM_CLIENT;
    int remaining = NUM_MESSAGE % NUM_WORKER;
    if(remaining > WORKER_ID) {
        global_start_id += WORKER_ID;
        NUM_CLIENT++;
    } else {
        global_start_id += remaining;
    }

    global_end_id = MIN((global_start_id + NUM_CLIENT), NUM_MESSAGE);
    active_client_interval = (NUM_MESSAGE / NUM_ACTIVE_CLIENT);
    active_client_this_worker = ceil((double)global_end_id / active_client_interval) - ceil((double)global_start_id/ active_client_interval);
    active_client_start = ((int)ceil((double)global_start_id/active_client_interval)) * active_client_interval - global_start_id;

    preprocessing_time = new uint64_t[NUM_ROUND];
    generation_time = new uint64_t[NUM_ROUND];
    db_recv_timestamp = new uint64_t[NUM_ROUND];
    response_send_timestamp = new uint64_t[NUM_ROUND];

    NUM_COLUMNS = (ceil((double)(MESSAGE_SIZE * 4) / (PLAIN_BIT - 1)) * 2);
    DB_ROWS = (NUM_CT_PER_QUERY * (NUM_COLUMNS/2));

    threads = new pthread_t [NUM_THREAD];
    thread_id = new int[NUM_THREAD];

    chrono::high_resolution_clock::time_point time_start, time_end, total_start, total_end;
    srand (time(NULL));

	EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(N);

    parms.set_coeff_modulus({COEFF_MODULUS_54, COEFF_MODULUS_55});    
    parms.set_plain_modulus(PLAIN_MODULUS); 
    context = SEALContext::Create(parms);
 
    batch_encoder = new BatchEncoder(context);
    evaluator = new Evaluator(context);
    encoded_db = new Plaintext[DB_ROWS];
    result = new Ciphertext[NUM_CLIENT];
 
    uint64_t add_time = 0, mult_time = 0, rot_time = 0, total_time = 0, ntt_time = 0;
    Ciphertext temp_ct;
    Plaintext temp_pt;


    pid = context->first_parms_id();
    active_clients = new rpc::client*[active_client_this_worker];
    int c_id = ((int)ceil((double)global_start_id/active_client_interval));
    for(int i = 0;i < active_client_this_worker;i++, c_id ++) {
        active_clients[i] = new rpc::client(CLIENT_IP, CLIENT_PORT + c_id);
    }
    rpc::client db_client(MASTER_IP, MASTER_PORT + WORKER_ID);
 

    pthread_barrier_init(&preprocess_barrier,NULL,1 + NTT_NUM_THREAD);
    pthread_barrier_init(&pir_barrier,NULL,1 + NUM_THREAD);

    keygen = new KeyGenerator(context);
    gal_keys = new GaloisKeys[NUM_CLIENT];
    secret_key = keygen->secret_key();  
    encryptor = new Encryptor(context, secret_key);
    query = new Ciphertext*[NUM_CLIENT];

    for(int i = 0;i<NUM_THREAD;i++) {
        thread_id[i] = i;
        if(pthread_create(&threads[i], NULL, gen_keys, (void *)&thread_id[i])) {
            printf("Error creating thread\n");
            exit(1);
        }
    }

    for(int i = 0;i<NUM_THREAD;i++) {
        pthread_join(threads[i], NULL);
    }
    string reply = db_client.call("sendDB", -1).as<string>();
    raw_db = reply.data();

    for(int i = 0;i<NUM_THREAD;i++) {
        //thread_id[i] = i;
        if(pthread_create(&threads[i], NULL, pir, (void *)&thread_id[i])) {
            printf("Error creating thread\n");
            exit(1);
        }
    }

    for(int i = 0; i < NTT_NUM_THREAD;i++) {
        ntt_thread_id[i] = i;
        if(pthread_create(&ntt_threads[i], NULL, preprocess_db, (void *)&ntt_thread_id[i])) {
            printf("Error creating thread for DB NTT transform\n");           
            exit(1);
        }
    }
    
    // populate_galois_keys();
    // populate_queries();
    cout<<"Generated dialing data\n";

    total_cpu_start_time = clock();
    while(current_round < NUM_ROUND) {
        time_start = chrono::high_resolution_clock::now();
        //cout<<"Starting round "<<current_round+1<<endl;
        //std::string reply = db_client.sendDB(1 + current_round);
        reply = db_client.call("sendDB", ++current_round).as<string>();
        db_recv_timestamp[current_round - 1] = chrono::duration_cast<chrono::microseconds>(chrono::high_resolution_clock::now().time_since_epoch()).count();
        raw_db = reply.data();
        //cout<<"received DB round "<<current_round<<" size "<<reply.size()<<endl;
        time_start = chrono::high_resolution_clock::now();
        cpu_start_time = clock();
        pthread_mutex_lock(&preprocess_lock);
        ++preprocessing_round;
        pthread_cond_broadcast(&preprocess_cond);
        pthread_mutex_unlock(&preprocess_lock);
        pthread_barrier_wait(&preprocess_barrier);
        cpu_stop_time = clock();
        preprocessing_cpu_time += (cpu_stop_time - cpu_start_time);
        // for (int i = 0; i < NTT_NUM_THREAD; ++i) {
        //     pthread_join(ntt_threads[i], NULL);
        // }
        time_end = chrono::high_resolution_clock::now();
        preprocessing_time[current_round-1] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();

        time_start = chrono::high_resolution_clock::now();
        cpu_start_time = clock();
        pthread_mutex_lock(&pir_lock);
        ++pir_round;
        pthread_cond_broadcast(&pir_cond);
        pthread_mutex_unlock(&pir_lock);
        pthread_barrier_wait(&pir_barrier);
        cpu_stop_time = clock();
        reply_cpu_time += (cpu_stop_time - cpu_start_time);
        // for (int i = 0; i < NUM_THREAD; ++i) {
        //     pthread_join(threads[i], NULL);
        // }
        time_end = chrono::high_resolution_clock::now();
        generation_time[current_round-1] = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
        time_start = chrono::high_resolution_clock::now();
        //ct_client.async_call("sendCT",ct);
        //response_send_timestamp[current_round-1] = chrono::duration_cast<chrono::microseconds> (time_start.time_since_epoch()).count();
        //cout<<"Finished round: "<<current_round<<endl;
    }

    for(int i = 0;i<NUM_THREAD;i++) {
        pthread_join(threads[i], NULL);
    }
    total_cpu_stop_time = clock();

    printReport();
   
    // cout<<"DB Preprocessing time: "<<preprocessing_time<<endl;
    // cout<<"Total Reply generation time: "<<total_time<<endl;
    // cout<<"Response sending time "<<ct_send_time<<endl;

    // cout<<"Number of bits in each co-effcient: "<<PLAIN_BIT-1<<endl;
    // cout<<"Number of co-efficcients retrieved: "<<NUM_COLUMNS<<endl;
    // cout<<"Number of bits retrieved: "<<((PLAIN_BIT-1) * NUM_COLUMNS)<<endl;
    

	return 0;
}


void *pir(void *thread_id) {  

    Ciphertext column_sum, temp_ct;
    column_sum = query[0][0]; //Allocate memory
    temp_ct = query[0][0]; // Allocate memory
    int client_factor = floor((double)NUM_CLIENT/NUM_THREAD);
    int start_id = *((int *)thread_id) * client_factor;
    int remaining = NUM_CLIENT % NUM_THREAD;
    if(remaining > *((int *)thread_id)) {
        start_id += *((int *)thread_id);
        client_factor++;
    }else {
        start_id += remaining;
    }
    int end_id = MIN((start_id + client_factor), NUM_CLIENT);
    stack<Ciphertext> st;
    int my_round = 1;
    vector<uint64_t> ct(2*N);

    for(int client_id = start_id; client_id < end_id ; client_id++) {
        result[client_id] = query[client_id][0]; // TO allocate memory
        if((client_id - active_client_start)%active_client_interval == 0) {
            result[client_id] = query[client_id][0];
            std::copy(result[client_id].data(), result[client_id].data() +(2 * N), ct.begin());
            active_clients[((client_id - active_client_start)/active_client_interval)]->async_call("sendCT",ct);
        }
 
    }

    while(my_round <= NUM_ROUND) { 
        pthread_mutex_lock(&pir_lock);
        while (pir_round != my_round) {     
            pthread_cond_wait(&pir_cond, &pir_lock);
        }
        pthread_mutex_unlock(&pir_lock);

        // Compact implementation of FastPIR functionalities
   
        for(int client_id = start_id; client_id < end_id; client_id++) {
            for(int i = 0; i < NUM_COLUMNS/2;i++) {
                evaluator->multiply_plain(query[client_id][0], encoded_db[NUM_CT_PER_QUERY*i ], column_sum);
                for(int j = 1; j < NUM_CT_PER_QUERY; j++) {
                    evaluator->multiply_plain(query[client_id][j], encoded_db[NUM_CT_PER_QUERY*i + j], temp_ct);
                    evaluator->add_inplace(column_sum, temp_ct);
                }
                evaluator->transform_from_ntt_inplace(column_sum);

                // Iterative implementation of FastPIR's tree optimization

                int k = i+1;
                int step_size = -1;

                while(k%2 == 0) {
                    Ciphertext xx = st.top();
                    st.pop();
                    evaluator->rotate_rows_inplace(column_sum, step_size, gal_keys[client_id]);
                    evaluator->add_inplace(column_sum, xx);
                    k /= 2;
                    step_size *= 2;
                }
                st.push(column_sum);
            }        
            result[client_id] = st.top();
            st.pop();
            int mask = NUM_COLUMNS/2;
            mask &= (mask -1); // Reset rightmost bit
            while(mask && st.size()) {
                int step_size = - (mask & ~(mask-1)); // Only setting the rightmost 1
                evaluator->rotate_rows_inplace(result[client_id], step_size, gal_keys[client_id]);
                Ciphertext xx = st.top();
                st.pop();
                evaluator->add_inplace(result[client_id], xx);
                mask &= (mask -1); // Reset rightmost bit
            }
        }
        ++my_round;
        pthread_barrier_wait(&pir_barrier);

        for(int client_id = start_id; client_id < end_id ; client_id++) {
            if((client_id - active_client_start)%active_client_interval == 0) {
                std::copy(result[client_id].data(), result[client_id].data() +(2 * N), ct.begin());
                active_clients[((client_id - active_client_start)/active_client_interval)]->async_call("sendCT",ct);
            }
        }

    }

    //sleep(5);

    return 0;
}

void *preprocess_db(void *thread_id) {

    int client_factor = floor((double)DB_ROWS/NTT_NUM_THREAD);
    int start_id = *((int *)thread_id) * client_factor;
    int remaining = DB_ROWS % NTT_NUM_THREAD;
    if(remaining > *((int *)thread_id)) {
        start_id += *((int *)thread_id);
        client_factor++;
    } else {
        start_id += remaining;
    }

    int end_id = MIN((start_id + client_factor), DB_ROWS);
    vector<uint64_t> db_element(N);
    int my_round = 1;

    while(my_round <= NUM_ROUND) {
        pthread_mutex_lock(&preprocess_lock);
        while (preprocessing_round != my_round) {     
            pthread_cond_wait(&preprocess_cond, &preprocess_lock);
        }
        pthread_mutex_unlock(&preprocess_lock);

        for(int row = start_id;row < end_id;row++) {
            for(int j = 0; j < N; j++) {
                //db_element[j] = rand()%(1<<(PLAIN_BIT-1));
                db_element[j] = raw_db[j & (RAW_DB_SIZE -1)]+row + my_round * 7;
            }

            encoded_db[row].release();
            batch_encoder->encode(db_element, encoded_db[row]);
            evaluator->transform_to_ntt_inplace(encoded_db[row], pid);
        }
        ++my_round;
        pthread_barrier_wait(&preprocess_barrier);
    }

    return 0;
}

// void populate_galois_keys() {
//     keygen = new KeyGenerator(context);
//     gal_keys = new GaloisKeys[NUM_CLIENT];
//     for(int i = 0;i<NUM_CLIENT;i++) {
//         gal_keys[i] = keygen->galois_keys_local();
//     }
// }

// void populate_queries() {
    
//     SecretKey secret_key = keygen->secret_key();   
//     Encryptor encryptor(context, secret_key);
//     int index = 2050;
//     size_t row_size = N / 2;
//     query = new Ciphertext*[NUM_CLIENT];
//     for(int i =0; i < NUM_CLIENT;i++) {
//         query[i] = new Ciphertext[NUM_CT_PER_QUERY];
        
//         Plaintext pt;

//         for(int j = 0; j < NUM_CT_PER_QUERY; j++) {
//             vector<uint64_t> pod_matrix(N, 0ULL);
//             if((index/row_size) == j) {
//                 pod_matrix[index%row_size] = 1;
//                 pod_matrix[row_size + (index%row_size)] = 1;
//             }
//             //print_matrix(pod_matrix, row_size);
//             batch_encoder->encode(pod_matrix, pt);
//             encryptor.encrypt_symmetric(pt, query[i][j]);
//             evaluator->transform_to_ntt_inplace(query[i][j]);
//         }
//     }

//     return;
// }
    

void *gen_keys(void *thread_id) {
    
    size_t row_size = N / 2;
    int client_factor = floor((double)NUM_CLIENT/NUM_THREAD);
    int start_id = *((int *)thread_id) * client_factor;
    int remaining = NUM_CLIENT % NUM_THREAD;
    if(remaining > *((int *)thread_id)) {
        start_id += *((int *)thread_id);
        client_factor++;
    }else {
        start_id += remaining;
    }
    int end_id = MIN((start_id + client_factor), NUM_CLIENT);

    for(int client_id = start_id; client_id < end_id;client_id++) {
        int index = rand()%NUM_CLIENT;
        gal_keys[client_id] = keygen->galois_keys_local();

        query[client_id] = new Ciphertext[NUM_CT_PER_QUERY];
        
        Plaintext pt;

        for(int j = 0; j < NUM_CT_PER_QUERY; j++) {
            vector<uint64_t> pod_matrix(N, 0ULL);
            if((index/row_size) == j) {
                pod_matrix[index%row_size] = 1;
                pod_matrix[row_size + (index%row_size)] = 1;
            }
            //print_matrix(pod_matrix, row_size);
            batch_encoder->encode(pod_matrix, pt);
            encryptor->encrypt_symmetric(pt, query[client_id][j]);
            evaluator->transform_to_ntt_inplace(query[client_id][j]);
        }
    }


}

void printReport() {
    cout<<"\nClock time: \nPreprocessing\tResponse\tTotal\t(us)\n";
    for(int i = 0;i<NUM_ROUND;i++) {
        cout<<preprocessing_time[i]<<"\t"<<generation_time[i]<<"\t"<<preprocessing_time[i]+generation_time[i]<<endl;
    }

    cout<<"\nTotal CPU time (all subrounds): \nPreprocessing\tResponse\tTotal\t(sec)\n";   
    cout<<(float)preprocessing_cpu_time/CLOCKS_PER_SEC<<"\t"<<(float)reply_cpu_time/CLOCKS_PER_SEC<<"\t"<<(float)(preprocessing_cpu_time + reply_cpu_time)/CLOCKS_PER_SEC<<endl;

    //cout<<"Total CPU time including overheads:(sec)\n"<<((float)total_cpu_stop_time-total_cpu_start_time)/CLOCKS_PER_SEC;


    // cout<<"\nDB recv timestamp\n";
    // for(int i = 0;i<NUM_ROUND;i++) {
    //     cout<<db_recv_timestamp[i]<<endl;
    // }

    // cout<<"\nResponse send timestamp\n\n";
    // for(int i = 0;i<NUM_ROUND;i++) {
    //     cout<<response_send_timestamp[i]<<endl;
    // }
    return;
}
