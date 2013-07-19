#ifndef _WSGATE_MYFREERDP_H_
#define _WSGATE_MYFREERDP_H_

// libfreerdp internal headers

enum CONNECTION_STATE
{
	CONNECTION_STATE_INITIAL = 0,
	CONNECTION_STATE_NEGO,
	CONNECTION_STATE_MCS_CONNECT,
	CONNECTION_STATE_MCS_ERECT_DOMAIN,
	CONNECTION_STATE_MCS_ATTACH_USER,
	CONNECTION_STATE_MCS_CHANNEL_JOIN,
	CONNECTION_STATE_ESTABLISH_KEYS,
	CONNECTION_STATE_LICENSE,
	CONNECTION_STATE_CAPABILITY,
	CONNECTION_STATE_FINALIZATION,
	CONNECTION_STATE_ACTIVE
};

enum RDP_NEG_PROTOCOLS
{
	PROTOCOL_RDP = 0x00000000,
	PROTOCOL_TLS = 0x00000001,
	PROTOCOL_NLA = 0x00000002
};

enum _NEGO_STATE
{
	NEGO_STATE_INITIAL,
	NEGO_STATE_NLA, /* Network Level Authentication (TLS implicit) */
	NEGO_STATE_TLS, /* TLS Encryption without NLA */
	NEGO_STATE_RDP, /* Standard Legacy RDP Encryption */
	NEGO_STATE_FAIL, /* Negotiation failure */
	NEGO_STATE_FINAL
};
typedef enum _NEGO_STATE NEGO_STATE;

typedef struct rdp_transport rdpTransport;

struct rdp_nego
{
	int port;
	uint32 flags;
	char* hostname;
	char* cookie;
	NEGO_STATE state;
	int tcp_connected;
	rdpBlob* routing_token;
	uint32 selected_protocol;
	uint32 requested_protocols;
	uint8 enabled_protocols[3];
	rdpTransport* transport;
};

struct rdp_rdp
{
    int state;
    freerdp* instance;
    struct rdp_mcs* mcs;
    struct rdp_nego* nego;
    struct rdp_input* input;
    struct rdp_update* update;
    struct rdp_fastpath* fastpath;
    struct rdp_license* license;
    struct rdp_redirection* redirection;
    struct rdp_settings* settings;
    struct rdp_transport* transport;
    struct rdp_extension* extension;
    struct rdp_mppc_dec* mppc_dec;
    struct rdp_mppc_enc* mppc_enc;
    struct crypto_rc4_struct* rc4_decrypt_key;
    int decrypt_use_count;
    int decrypt_checksum_use_count;
    struct crypto_rc4_struct* rc4_encrypt_key;
    int encrypt_use_count;
    int encrypt_checksum_use_count;
    struct crypto_des3_struct* fips_encrypt;
    struct crypto_des3_struct* fips_decrypt;
    struct crypto_hmac_struct* fips_hmac;
    uint32 sec_flags;
    boolean do_crypt;
    boolean do_secure_checksum;
    uint8 sign_key[16];
    uint8 decrypt_key[16];
    uint8 encrypt_key[16];
    uint8 decrypt_update_key[16];
    uint8 encrypt_update_key[16];
    int rc4_key_len;
    uint8 fips_sign_key[20];
    uint8 fips_encrypt_key[24];
    uint8 fips_decrypt_key[24];
    uint32 errorInfo;
    uint32 finalize_sc_pdus;
    boolean disconnect;
};

typedef enum
{
	TRANSPORT_LAYER_TCP,
	TRANSPORT_LAYER_TLS,
	TRANSPORT_LAYER_CLOSED
} TRANSPORT_LAYER;

typedef boolean (*TransportRecv) (rdpTransport* transport, STREAM* stream, void* extra);

struct rdp_transport
{
	STREAM* recv_stream;
	STREAM* send_stream;
	TRANSPORT_LAYER layer;
	struct rdp_tcp* tcp;
	struct rdp_tls* tls;
	struct rdp_settings* settings;
	struct rdp_credssp* credssp;
	uint32 usleep_interval;
	void* recv_extra;
	STREAM* recv_buffer;
	TransportRecv recv_callback;
	struct wait_obj* recv_event;
	boolean blocking;
	boolean process_single_pdu; /* process single pdu in transport_check_fds */
};

rdpRdp* rdp_new(freerdp* instance);

void rdp_free(rdpRdp* rdp);

void transport_attach(rdpTransport* transport, int sockfd);
 
#endif
