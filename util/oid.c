#include <openssl/objects.h>
#include <openssl/core.h>
#include "util.h"

int register_oid(char *oid, char *name, char *description) {
    static int initialized = 0;
    if (!initialized) {
        int nid = OBJ_create(oid, name, description);
        if (nid != NID_undef) {
            initialized = 1;
            return nid;
        }
    }
    return OBJ_txt2nid(name);
}