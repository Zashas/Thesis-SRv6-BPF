#include <stdint.h>
#include <stddef.h>
#include <linux/seg6_local.h>

#include "bpf_api.h"
//#include "proto.h"

/* Packet parsing state machine helpers. */
#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

#define SR6_FLAG_PROTECTED (1 << 6)
#define SR6_FLAG_OAM (1 << 5)
#define SR6_FLAG_ALERT (1 << 4)
#define SR6_FLAG_HMAC (1 << 3)
