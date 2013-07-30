#include "RDPReverseServer.hpp"

namespace wsgate {
    
    // public:
    
    RDPReverseServer::RDPReverseServer(std::string cert_file, std::string key_file,
            std::string ca_file)
        : m_cert_file(cert_file)
        , m_key_file(key_file)
        , m_ca_file(ca_file)
        , m_worker()
    {
        
    }
    
    RDPReverseServer::~RDPReverseServer() {
        
    }
    
    void RDPReverseServer::StartServer() {
        if ((m_sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
            log::err << "Could not create server socket" << std::endl;
            return;
        }
        memset(&m_server_addr, 0, sizeof(m_server_addr));
        m_server_addr.sin_family      = AF_INET;
        m_server_addr.sin_addr.s_addr = INADDR_ANY;
        m_server_addr.sin_port        = htons(4489);
 
        if (bind(m_sockfd, (struct sockaddr*) &m_server_addr, sizeof(m_server_addr)) == -1) {
            log::err << "Could not bind server socket" << std::endl;
            return;
        }
 
        if (listen(m_sockfd, SOMAXCONN) == -1) {
            log::err << "Could not listen on server socket" << std::endl;
            return;
        }

        log::info << "Reverse server listening on 4489" << std::endl;
        
        if (0 != pthread_create(&m_worker, NULL, cbServerThreadFunc, reinterpret_cast<void *>(this))) {
            log::err << "Could not create RDP reverse server thread" << std::endl;
        } else {
            log::debug << "Created RDP reverse server thread" << std::endl;
        }
    }
    
    rdpTls *RDPReverseServer::PopPeer(std::string key) {
        boost::unordered_map<std::string, rdpTls*>::iterator it;
        rdpTls *peer = NULL;
        
        m_peers_map_mtx.lock();
        it = m_peers_map.find(key);
        if (m_peers_map.end() != it) {
            m_peers_map.erase(it);
            peer = it->second;
        }
        m_peers_map_mtx.unlock();
        
        return peer;
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
        SSL_CTX* ctx;
        SSL* ssl;
        int ssl_status;
        X509 *peer_cert;
        char buf[256];
        rdpTls* peer_tls;
        
        SSL_library_init();
        SSL_load_error_strings();
        
        ctx = SSL_CTX_new(TLSv1_server_method());
        if (!SSL_CTX_load_verify_locations(ctx, m_ca_file.c_str(), NULL)) {
            log::err << "Could not load server trusted CA" << std::endl;
            return;
        }
        
        if (SSL_CTX_use_certificate_file(ctx, m_cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
            log::err << "Could not load server cert" << std::endl;
            return;
        }
        
        // Load the server private-key into the SSL context
        if (SSL_CTX_use_PrivateKey_file(ctx, m_key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
            log::err << "Could not load server private key" << std::endl;
            return;
        }
        
        // Set to require peer (client) certificate verification
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        // Set the verification depth to 1
        SSL_CTX_set_verify_depth(ctx, 1);
        
        while(1) {
            new_fd = accept(m_sockfd, (struct sockaddr*) &new_addr, &addr_size);
            if (new_fd == -1) {
                log::err << "Failed accepting connection" << std::endl;
                continue;
            }
            char* new_host = (char*) malloc(INET_ADDRSTRLEN);
            char* new_port = (char*) malloc(6);
            struct sockaddr_in* sa = (struct sockaddr_in*) &new_addr;
            inet_ntop(AF_INET, &(sa->sin_addr), new_host, INET_ADDRSTRLEN);
            sprintf(new_port, "%u", sa->sin_port);
            log::info << "New connection " << new_host << ":" << new_port << std::endl;

            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, new_fd);
            ssl_status = SSL_accept(ssl);
            if (ssl_status <= 0) {
                PrintSSLError("SSL_connect", ssl, ssl_status);
                SSL_shutdown(ssl);
                SSL_free(ssl);
                continue;
            }
            
            if ((peer_cert = SSL_get_peer_certificate(ssl)) != NULL) {
                X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert), OBJ_txt2nid("CN"), buf, 256);
                log::info << "Proxy cert CN: " << buf << std::endl;
                
                if (X509_V_OK == SSL_get_verify_result(ssl)) {
                    
                    peer_tls = (rdpTls*) malloc(sizeof(rdpTls));
                    peer_tls->ssl = ssl;
                    peer_tls->sockfd = new_fd;
                    peer_tls->ctx = ctx;
                    
                    std::string key(buf);
                    
                    // close existing connection for this peer
                    rdpTls *peer = this->PopPeer(key);
                    if (NULL != peer) {
                        log::info << "Closing existing peer connection, key: " << key << std::endl;
                        SSL_shutdown(peer->ssl);
                        SSL_free(peer->ssl);
                        shutdown(peer->sockfd, SHUT_RDWR);
                        close(peer->sockfd);
                        free(peer);
                    }
                    
                    m_peers_map_mtx.lock();
                    m_peers_map[key] = peer_tls;
                    m_peers_map_mtx.unlock();
                    
                    log::info << "SSL connection established " << new_host << ":" << new_port << std::endl;    
                } else {
                    log::err << "Failed client verification with SSL_get_verify_result" << std::endl;
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                }
            } else {
                log::err << "Peer cert was not presented" << std::endl;
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            
        }
        
        SSL_CTX_free(ctx);
    }
    
    bool RDPReverseServer::PrintSSLError(char* func, SSL* connection, int value)
    {
        switch (SSL_get_error(connection, value))
        {
            case SSL_ERROR_ZERO_RETURN:
                log::err << func <<": Server closed TLS connection\n" << std::endl;
                return true;

            case SSL_ERROR_WANT_READ:
                log::info << "SSL_ERROR_WANT_READ\n" << std::endl;
                return false;

            case SSL_ERROR_WANT_WRITE:
                log::info << "SSL_ERROR_WANT_WRITE\n" << std::endl;
                return false;

            case SSL_ERROR_SYSCALL:
                log::err << func << ": I/O error\n" << std::endl;
                return true;

            case SSL_ERROR_SSL:
                log::err << func << ": Failure in SSL library (protocol error?)\n" << std::endl;
                return true;

            default:
                log::err << func << ": Unknown error\n" << std::endl;
                return true;
        }
    }

}
