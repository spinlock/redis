#include "server.h"

/* MIGRATE       host port key dbid timeout [COPY | REPLACE | AUTH password]
 * MIGRATE-ASYNC host port key dbid timeout [COPY | REPLACE | AUTH password]
 *
 * On in the multiple keys form:
 *
 * MIGRATE       host port "" dbid timeout [COPY | REPLACE | AUTH password] KEYS
 * key1 key2 ... keyN
 * MIGRATE-ASYNC host port "" dbid timeout [COPY | REPLACE | AUTH password] KEYS
 * key1 key2 ... keyN */
typedef struct {
    int dbid;
    robj* auth;
    int copy, replace;
    long timeout;
    dict* keys;
} migrateCommandArgs;

static migrateCommandArgs* initMigrateCommandArgs(void) {
    return zcalloc(sizeof(migrateCommandArgs));
}

extern void decrRefCountLazyfree(robj* obj);

static void freeMigrateCommandArgs(migrateCommandArgs* args) {
    if (args->auth != NULL) {
        decrRefCount(args->auth);
    }
    if (args->keys != NULL) {
        dictIterator* it = dictGetIterator(args->keys);
        dictEntry* entry;
        while ((entry = dictNext(it)) != NULL) {
            robj* obj = dictGetVal(entry);
            decrRefCountLazyfree(obj);
        }
        dictReleaseIterator(it);
        dictRelease(args->keys);
    }
    zfree(args);
}

static int parseMigrateCommand(client* c, migrateCommandArgs* args) {
    /* To support the KEYS option we need the following additional state. */
    int first_key = 3; /* Argument index of the first key. */
    int num_keys = 1;  /* By default only migrate the 'key' argument. */

    /* Parse additional options */
    for (int j = 6; j < c->argc; j++) {
        int moreargs = j < c->argc - 1;
        if (!strcasecmp(c->argv[j]->ptr, "copy")) {
            args->copy = 1;
        } else if (!strcasecmp(c->argv[j]->ptr, "replace")) {
            args->replace = 1;
        } else if (!strcasecmp(c->argv[j]->ptr, "auth")) {
            if (!moreargs) {
                addReply(c, shared.syntaxerr);
                return C_ERR;
            }
            j++;
            args->auth = c->argv[j]->ptr;
            incrRefCount(args->auth);
        } else if (!strcasecmp(c->argv[j]->ptr, "keys")) {
            if (sdslen(c->argv[3]->ptr) != 0) {
                addReplyError(c,
                              "When using MIGRATE KEYS option, the key argument"
                              " must be set to the empty string");
                return C_ERR;
            }
            first_key = j + 1;
            num_keys = c->argc - j - 1;
            break; /* All the remaining args are keys. */
        } else {
            addReply(c, shared.syntaxerr);
            return C_ERR;
        }
    }

    long dbid, timeout;

    /* Sanity check */
    if (getLongFromObjectOrReply(c, c->argv[5], &timeout, NULL) != C_OK ||
        getLongFromObjectOrReply(c, c->argv[4], &dbid, NULL) != C_OK) {
        return C_ERR;
    }
    args->dbid = dbid;
    args->timeout = (timeout <= 0) ? 1000 : timeout;

    /* Check if the keys are here. If at least one key is to migrate, do it
     * otherwise if all the keys are missing reply with "NOKEY" to signal
     * the caller there was nothing to migrate. We don't return an error in
     * this case, since often this is due to a normal condition like the key
     * expiring in the meantime. */

    args->keys = dictCreate(&objectKeyPointerValueDictType, NULL);
    for (int j = 0; j < num_keys; j++) {
        robj* key = c->argv[first_key + j];
        robj* obj = lookupKeyRead(c->db, key);
        if (obj != NULL && dictAdd(args->keys, key, obj) != C_ERR) {
            incrRefCount(key);
            incrRefCount(obj);
        }
    }
    if (dictSize(args->keys) == 0) {
        addReplySds(c, sdsnew("+NOKEY\r\n"));
        return C_ERR;
    }

    /* Rehash the keys dict if it's rehashing. */
    dictRehash(args->keys, 100);
    return C_OK;
}
