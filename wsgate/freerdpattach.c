#include "freerdpattach.h"

int freerdp_attach(freerdp* instance)
{
	rdpRdp* rdp;
	boolean status = false;

	rdp = instance->context->rdp;

	extension_pre_connect(rdp->extension);

	IFCALLRET(instance->PreConnect, status, instance);

	if (status != true)
	{
		printf("freerdp_pre_connect failed\n");
		return false;
	}

	status = rdp_attach_client_connect(rdp);

	if (status)
	{
		if (instance->settings->dump_rfx)
		{
			instance->update->pcap_rfx = pcap_open(instance->settings->dump_rfx_file, true);
			if (instance->update->pcap_rfx)
				instance->update->dump_rfx = true;
		}

		extension_post_connect(rdp->extension);

		IFCALLRET(instance->PostConnect, status, instance);

		if (status != true)
		{
			printf("freerdp_post_connect failed\n");
			return false;
		}

		if (instance->settings->play_rfx)
		{
			STREAM* s;
			rdpUpdate* update;
			pcap_record record;

			s = stream_new(1024);
			instance->update->pcap_rfx = pcap_open(instance->settings->play_rfx_file, false);
			if (instance->update->pcap_rfx)
				instance->update->play_rfx = true;
			update = instance->update;

			while (instance->update->play_rfx && pcap_has_next_record(update->pcap_rfx))
			{
				pcap_get_next_record_header(update->pcap_rfx, &record);

				s->data = xrealloc(s->data, record.length);
				record.data = s->data;
				s->size = record.length;

				pcap_get_next_record_content(update->pcap_rfx, &record);
				stream_set_pos(s, 0);

				update->BeginPaint(update->context);
				update_recv_surfcmds(update, s->size, s);
				update->EndPaint(update->context);
			}

			xfree(s->data);
			return true;
		}
	}

	return status;
}

int rdp_attach_client_connect(rdpRdp* rdp)
{
	boolean status;
	uint32 selectedProtocol;
	rdpSettings* settings = rdp->settings;

    
	nego_init(rdp->nego);
    
    rdp->nego->tcp_connected = 1;
     
	nego_set_target(rdp->nego, settings->hostname, settings->port);
	nego_set_cookie(rdp->nego, settings->username);
	nego_enable_rdp(rdp->nego, settings->rdp_security);
	nego_enable_nla(rdp->nego, settings->nla_security);
	nego_enable_tls(rdp->nego, settings->tls_security);

	if (nego_connect(rdp->nego) != true)
	{
		printf("Error: protocol security negotiation failure\n");
		return false;
	}

	selectedProtocol = rdp->nego->selected_protocol;

	if ((selectedProtocol & PROTOCOL_TLS) || (selectedProtocol == PROTOCOL_RDP))
	{
		if ((settings->username != NULL) && ((settings->password != NULL) || (settings->password_cookie != NULL && settings->password_cookie->length > 0)))
			settings->autologon = true;
	}

	status = false;
	if (selectedProtocol & PROTOCOL_NLA)
		status = transport_connect_nla(rdp->transport);
	else if (selectedProtocol & PROTOCOL_TLS)
		status = transport_connect_tls(rdp->transport);
	else if (selectedProtocol == PROTOCOL_RDP) // 0
		status = transport_connect_rdp(rdp->transport);

	if (status != true)
		return false;
    
	rdp_set_blocking_mode(rdp, false);
	rdp->state = CONNECTION_STATE_NEGO;
	rdp->finalize_sc_pdus = 0;

	if (mcs_send_connect_initial(rdp->mcs) != true)
	{
		printf("Error: unable to send MCS Connect Initial\n");
		return false;
	}

	rdp->transport->process_single_pdu = true;
	while (rdp->state != CONNECTION_STATE_ACTIVE)
	{
		if (rdp_check_fds(rdp) < 0)
			return false;
	}
	rdp->transport->process_single_pdu = false;

	return true;
}

int freerdp_detach(freerdp* instance) {
    rdpTransport *transport = instance->context->rdp->transport;
    
    if (transport->layer == TRANSPORT_LAYER_TLS)
        tls_disconnect(transport->tls);
    
    return 1;
}
