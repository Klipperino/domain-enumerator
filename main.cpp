//g++ main.cpp -lldns -o dnsenum
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstring>
#include <regex>
#include <ldns/ldns.h>
#include <chrono>
#include <thread>

using namespace std;

string domain;

FILE* open_wordlist(const char *path){
    FILE* fileptr = fopen(path, "r");
    if(!fileptr){
        cerr << "File could not be opened." << endl;
        exit(1);
    }
    return fileptr;
}

void save_to_file(FILE* output_file, const char *content){
    int rc = fputs(content, output_file);
    if(rc == EOF){
        cerr << "Could not write to file." << endl;
    }
}

bool is_domain_valid(string dmn){
    regex pattern("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\\.)+[a-zA-Z]{2,}$");

    return regex_match(dmn, pattern);
}

int main(int argc, char *argv[]) {
    const char *wordlist;
    int rate = 5;
    FILE* output_file = NULL;
    
    for(int i = 1; i < argc; i++){
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0){
            cout << "Domain enumerator. Only use with explicit, written authorization from the owner of the server or computer you are scanning. Otherwise it is a criminal activity.\n" << endl;
            cout << "-h --help\t\tDisplays manual." << endl;
            cout << "-d --domain\t\tDefine domain to be scanned." << endl;
            cout << "-w --wordlist\t\tProvide a wordlist." << endl;
            cout << "-r --rate\t\tDefine a rate limit. Default: 5/s." << endl;
            cout << "-o\t\tOutput to filename." << endl;
            cout << "Example: dmnenum -d domain.com -w /home/user/downloads/wordlist.txt -o /home/user/documents/result.txt" << endl;
            return 1;
        }else if ((strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--domain") == 0) && i + 1 < argc){
            i++;
            const char *dmn = argv[i];
            string domain_string = dmn;
            if(strncmp(dmn, "http://", 7) == 0){
                domain_string.erase(0, 7);
            }else if(strncmp(dmn, "https://", 8) == 0){
                domain_string.erase(0, 8);
            }

            if (!is_domain_valid(domain_string)){
                cerr << "Invalid domain name." << endl;
                return 1;
            }

            domain = domain_string;
        }else if((strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--wordlist") == 0) && i + 1 < argc) {
            wordlist = argv[++i];
        }else if((strcmp(argv[i], "-o" ) == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc){
            i++;
            output_file = fopen(argv[i], "w");
            if(!output_file){
                cerr << "Could not create output file." << endl;
                return 1;
            }
            save_to_file(output_file, "Domain enumerator test results:\n");
        }else if((strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--rate") == 0) && i + 1 < argc){
            ++i;
            char *endptr;
            long rate_num = strtol(argv[i], &endptr, 10);

            if(*endptr != '\0'){
                cerr << "Error: '" << argv[i] << "' is not a rate parameter." << endl;
                return 1;
            }
            if(rate_num < 1 || rate_num > 999){
                cerr << "Error: rate limiting must be between 1 and 999." << endl;
                return 1;
            }
            rate = rate_num;
        }
    }

    if(domain.empty()){
        cerr << "No domain provided. Use -d to provide a domain." << endl;
        return 1;
    }

    if(wordlist == NULL){
        cerr << "No wordlist provided. Use -w to provide a wordlist." << endl;
        return 1;
    }

    FILE* wl = open_wordlist(wordlist);

    ldns_resolver *resolver = NULL;
    ldns_status status = ldns_resolver_new_frm_file(&resolver, NULL);
    if(status != LDNS_STATUS_OK){
        cerr << "Could not create resolver" << endl;
        return 1;
    }

    char line[265];
    auto last_query = chrono::steady_clock::now();
    while(fgets(line, sizeof(line), wl)){
        //rate limiting
        auto now = chrono::steady_clock::now();
        auto elapsed = chrono::duration_cast<chrono::milliseconds>(now - last_query);
        long interval = 1000 / rate;
        if(elapsed.count() < interval){
            this_thread::sleep_for(chrono::milliseconds(interval - elapsed.count()));
        }
        last_query = chrono::steady_clock::now();

        line[strcspn(line, "\n")] = 0;

        string subdomain = string(line) + "." + domain;

        if(!is_domain_valid(subdomain)){
            cout << subdomain << endl;
            cerr << "Invalid subdomain. Continueing..." << endl;
            continue;
        }

        ldns_rdf *domain_rdf = ldns_dname_new_frm_str(subdomain.c_str());
        ldns_pkt *packet = ldns_resolver_query(resolver, domain_rdf, LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);

        if(packet){
            ldns_rr_list *answers = ldns_pkt_answer(packet);
            if(answers && ldns_rr_list_rr_count(answers) > 0){
                for(size_t i = 0; i < ldns_rr_list_rr_count(answers); i++){
                    ldns_rr *rr = ldns_rr_list_rr(answers, i);
                    if(ldns_rr_get_type(rr) == LDNS_RR_TYPE_A){
                        ldns_rdf *addr = ldns_rr_a_address(rr);
                        char *addr_str = ldns_rdf2str(addr);
                        cout << subdomain << " -> " << addr_str << endl;
                        if(output_file){
                            save_to_file(output_file, (subdomain+"\n").c_str());
                        }
                        free(addr_str);
                    }
                }
            }
            ldns_pkt_free(packet);
        }
        ldns_rdf_free(domain_rdf);
    }
    ldns_resolver_free(resolver);

    if(output_file) fclose(output_file);
    if(wl) fclose(wl);
}