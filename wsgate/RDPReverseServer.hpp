#ifndef _WSGATE_RDP_PEER_SERVER_H_
#define _WSGATE_RDP_PEER_SERVER_H_

#include <pthread.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <boost/unordered_map.hpp>
#include <mutex>

extern "C" {
#include <freerdp/listener.h>
#include <freerdp/peer.h>
#include <freerdp/crypto/tls.h>
}

#include <freerdp/freerdp.h>

#include "wsgate.hpp"

namespace wsgate {
    
    
    struct reverse_peer_context {
        rdpContext _p;
        
        void *ptr;
    };

    /**
     * Server for incomming connectins from proxy to rdp server.
     */
    class RDPReverseServer {
        
        private:
            std::string m_cert_file;
            std::string m_key_file;
            std::string m_ca_file;
            pthread_t m_worker;
            int m_sockfd;
            struct sockaddr_in m_server_addr;
            std::mutex m_peers_map_mtx;
            boost::unordered_map<std::string, rdpTls*> m_peers_map;
        
        public:
            RDPReverseServer(std::string cert_file, std::string key_file, std::string ca_file);
            virtual ~RDPReverseServer();
            void StartServer();
            rdpTls *PopPeer(std::string key);
        
        private:            
            static void *cbServerThreadFunc(void *ctx);
            static bool PrintSSLError(char* func, SSL* connection, int value);
            void ServerThreadFunc();
            
    };
}

#endif
