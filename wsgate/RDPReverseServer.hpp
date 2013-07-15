#ifndef _WSGATE_RDP_PEER_SERVER_H_
#define _WSGATE_RDP_PEER_SERVER_H_

#include <pthread.h>

extern "C" {
#include <freerdp/listener.h>
#include <freerdp/peer.h>
}
#include <freerdp/freerdp.h>

#include "wsgate.hpp"

namespace wsgate {

    /**
     * Server for incomming connectins from proxy to rdp server.
     */
    class RDPReverseServer {
        
        private:
            std::string m_cert_file;
            std::string m_key_file;
            pthread_t m_worker;
            freerdp_listener *m_listener;
        
        public:
        
            RDPReverseServer(std::string cert_file, std::string key_file);
            
            virtual ~RDPReverseServer();
            
            void StartServer();
        
        private:
            
            static void *cbServerThreadFunc(void *ctx);
            static void cbPeerAccepted(freerdp_listener *listener, freerdp_peer *client);
            static boolean cbPeerPostConnect(freerdp_peer *client);
            
            void ServerThreadFunc();
            void PeerAccepted(freerdp_peer *client);
        
    };
}

#endif
