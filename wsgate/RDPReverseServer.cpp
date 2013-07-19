#include "RDPReverseServer.hpp"


namespace wsgate {

    using namespace std;
    
    // public:
    
    RDPReverseServer::RDPReverseServer(std::string cert_file, std::string key_file)
        : m_cert_file(cert_file)
        , m_key_file(key_file)
        , m_worker()
    {
        
    }
    
    RDPReverseServer::~RDPReverseServer() {
        
    }
    
    void RDPReverseServer::StartServer() {
        if ((m_sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
            log::err << "Could not create server socket" << endl;
            return;
        }
        memset(&m_server_addr, 0, sizeof(m_server_addr));
        m_server_addr.sin_family      = AF_INET;
        m_server_addr.sin_addr.s_addr = INADDR_ANY;
        m_server_addr.sin_port        = htons(4489);
 
        if (bind(m_sockfd, (struct sockaddr*) &m_server_addr, sizeof(m_server_addr)) == -1) {
            log::err << "Could not bind server socket" << endl;
            return;
        }
 
        if (listen(m_sockfd, SOMAXCONN) == -1) {
            log::err << "Could not listen on server socket" << endl;
            return;
        }

        log::info << "Reverse server listening on 4489" << endl;
        
        if (0 != pthread_create(&m_worker, NULL, cbServerThreadFunc, reinterpret_cast<void *>(this))) {
            log::err << "Could not create RDP reverse server thread" << endl;
        } else {
            log::debug << "Created RDP reverse server thread" << endl;
        }
    }
    

    // private:

    void *RDPReverseServer::cbServerThreadFunc(void *ctx) {
        RDPReverseServer *self = reinterpret_cast<RDPReverseServer *>(ctx);
        if (self) {
            self->ServerThreadFunc();
        }
        return NULL;
    }
            
    void RDPReverseServer::ServerThreadFunc() {
        sockaddr_storage new_addr;
        socklen_t addr_size = sizeof new_addr;
        int new_fd = -1;
        
        while(1) {
            new_fd = accept(m_sockfd, (struct sockaddr*) &new_addr, &addr_size);
            if (new_fd == -1) {
                log::err << "Failed accepting connection" << endl;
                continue;
            }
            char* new_host = (char*) malloc(INET_ADDRSTRLEN);
            char* new_port = (char*) malloc(6);
            struct sockaddr_in* sa = (struct sockaddr_in*) &new_addr;
            inet_ntop(AF_INET, &(sa->sin_addr), new_host, INET_ADDRSTRLEN);
            sprintf(new_port, "%u", sa->sin_port);
            log::info << "New connection " << new_host << ":" << new_port << endl;
            
            // TODO
            m_peerfd = new_fd;
        }
    }
    
    void RDPReverseServer::cbPeerAccepted(freerdp_listener *listener, freerdp_peer *client) {
        RDPReverseServer *self = reinterpret_cast<RDPReverseServer *>(listener->param1);
        self->PeerAccepted(client);
    }
    
    void RDPReverseServer::PeerAccepted(freerdp_peer *client) {

    }
    
    int RDPReverseServer::GetPeer() {
        return m_peerfd;
    }

}
