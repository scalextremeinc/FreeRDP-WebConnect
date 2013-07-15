#include "RDPReverseServer.hpp"


namespace wsgate {

    using namespace std;
    
    // public:
    
    RDPReverseServer::RDPReverseServer(std::string cert_file, std::string key_file)
        : m_cert_file(cert_file)
        , m_key_file(key_file)
        , m_worker()
        , m_listener(freerdp_listener_new())
    {
        m_listener->PeerAccepted = cbPeerAccepted;
        m_listener->param1 = reinterpret_cast<void *>(this);
    }
    
    RDPReverseServer::~RDPReverseServer() {
        freerdp_listener_free(m_listener);
    }
    
    void RDPReverseServer::StartServer() {
        log::info << "Reverse server listening on 4489" << endl;
        if (m_listener->Open(m_listener, NULL, 4489)) {
            if (0 != pthread_create(&m_worker, NULL, cbServerThreadFunc, reinterpret_cast<void *>(this))) {
                log::err << "Could not create RDP reverse server thread" << endl;
            } else {
                log::debug << "Created RDP reverse server thread" << endl;
            }
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
        int i;
        int fds;
        int max_fds;
        int rcount;
        void* rfds[32];
        fd_set rfds_set;

        memset(rfds, 0, sizeof(rfds));

        while (1)
        {
            rcount = 0;

            if (m_listener->GetFileDescriptor(m_listener, rfds, &rcount) != 1)
            {
                log::err << "Failed to get FreeRDP file descriptor" << endl;
                break;
            }

            max_fds = 0;
            FD_ZERO(&rfds_set);

            for (i = 0; i < rcount; i++)
            {
                fds = (int)(long)(rfds[i]);

                if (fds > max_fds)
                    max_fds = fds;

                FD_SET(fds, &rfds_set);
            }

            if (max_fds == 0)
                break;

            if (select(max_fds + 1, &rfds_set, NULL, NULL, NULL) == -1)
            {
                /* these are not really errors */
                if (!((errno == EAGAIN) ||
                    (errno == EWOULDBLOCK) ||
                    (errno == EINPROGRESS) ||
                    (errno == EINTR))) /* signal occurred */
                {
                    log::err << "select failed" << endl;
                    break;
                }
            }

            if (m_listener->CheckFileDescriptor(m_listener) != 1)
            {
                log::err << "Failed to check FreeRDP file descriptor" << endl;
                break;
            }
        }

        m_listener->Close(m_listener);
    }
    
    void RDPReverseServer::cbPeerAccepted(freerdp_listener *listener, freerdp_peer *client) {
        RDPReverseServer *self = reinterpret_cast<RDPReverseServer *>(listener->param1);
        self->PeerAccepted(client);
    }
    
    void RDPReverseServer::PeerAccepted(freerdp_peer *client) {
        int fds;
        int max_fds;
        int rcount;
        void* rfds[32];
        fd_set rfds_set;
        rdpSettings* settings;

        memset(rfds, 0, sizeof(rfds));
        
        log::info << "Peer connecting: " << client->hostname << endl;

        freerdp_peer_context_new(client);
        
        settings = client->settings;        
        settings->cert_file = strdup(m_cert_file.c_str());
        settings->privatekey_file = strdup(m_key_file.c_str());
        settings->rdp_key_file = strdup(m_key_file.c_str());
        
        settings->nla_security = false;
        settings->rfx_codec = true;

        client->PostConnect = cbPeerPostConnect;
        
        client->Initialize(client);
                
        while (1)
        {
            rcount = 0;

            if (client->GetFileDescriptor(client, rfds, &rcount) != true)
            {
                log::err << "Failed to get FreeRDP file descriptor" << endl;
                break;
            }

            max_fds = 0;
            FD_ZERO(&rfds_set);

            for (int i = 0; i < rcount; i++)
            {
                fds = (int)(long)(rfds[i]);

                if (fds > max_fds)
                    max_fds = fds;

                FD_SET(fds, &rfds_set);
            }

            if (max_fds == 0)
                break;

            if (select(max_fds + 1, &rfds_set, NULL, NULL, NULL) == -1)
            {
                /* these are not really errors */
                if (!((errno == EAGAIN) ||
                    (errno == EWOULDBLOCK) ||
                    (errno == EINPROGRESS) ||
                    (errno == EINTR))) /* signal occurred */
                {
                    log::debug << "select failed" << endl;
                    break;
                }
            }

            if (client->CheckFileDescriptor(client) != true)
            {
                log::err << "Failed to check freerdp file descriptor" << endl;
                break;
            }
            
            //log::info << "Client connection state: " << client->context->rdp->state << endl;
        }

        log::info << "Peer disconnected: " << client->hostname << endl;

        client->Disconnect(client);

        freerdp_peer_context_free(client);
        freerdp_peer_free(client);
    }
    
    boolean RDPReverseServer::cbPeerPostConnect(freerdp_peer* client) {
        //RDPReverseServer *self = reinterpret_cast<RDPReverseServer *>(listener->param1);
        //self->PeerAccepted(client);
        log::info << "Peer connected: " << client->hostname << endl;
        // Return false here would stop the execution of the peer mainloop
        return true;
    }
    
    //RDPReverseServer::peerPostConnect(freerdp_peer* client) {
    //    log::info << "Peer connection ready" << endl;
    //}

}
