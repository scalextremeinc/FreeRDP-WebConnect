#ifndef __FREERDPATTACH_H
#define __FREERDPATTACH_H

#include <freerdp/freerdp.h>
#include "myfreerdp.h"

int freerdp_attach(freerdp* instance);

int rdp_attach_client_connect(rdpRdp* rdp);

#endif
