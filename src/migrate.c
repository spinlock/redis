#include "server.h"

extern void decrRefCountLazyfree(robj* obj);

// ---------------- RESTORE / RESTORE-ASYNC --------------------------------- //

struct _restoreCommandArgs {
    redisDb* db;
    robj* key;
    robj* obj;
    mstime_t ttl;
    int replace;
    int non_blocking;

    list* fragments;
    size_t total_bytes;

    robj* raw_bytes;

    time_t last_update_time;
    sds errmsg;

    const char* cmdstr;

    client* client;
    int processing;
};

static void freeRestoreCommandArgs(restoreCommandArgs* args) {
    if (args->key != NULL) {
        decrRefCount(args->key);
    }
    if (args->obj != NULL) {
        decrRefCountLazyfree(args->obj);
    }

    while (listLength(args->fragments) != 0) {
        listNode* head = listFirst(args->fragments);
        decrRefCount(listNodeValue(head));
        listDelNode(args->fragments, head);
    }
    listRelease(args->fragments);

    if (args->raw_bytes != NULL) {
        decrRefCount(args->raw_bytes);
    }
    if (args->errmsg != NULL) {
        sdsfree(args->errmsg);
    }
    zfree(args);
}

static restoreCommandArgs* initRestoreCommandArgs(client* c, robj* key,
                                                  mstime_t ttl, int replace,
                                                  int non_blocking) {
    restoreCommandArgs* args = zcalloc(sizeof(*args));
    args->db = c->db;
    args->key = key;
    args->ttl = ttl;
    args->replace = replace;
    args->non_blocking = non_blocking;
    args->fragments = listCreate();
    args->client = c;
    if (server.cluster_enabled) {
        args->cmdstr = non_blocking ? "RESTORE-ASYNC-ASKING" : "RESTORE-ASKING";
    } else {
        args->cmdstr = non_blocking ? "RESTORE-ASYNC" : "RESTORE";
    }
    incrRefCount(key);
    return args;
}

extern int verifyDumpPayload(unsigned char* p, size_t len);

static int restoreGenericCommandExtractPayload(restoreCommandArgs* args) {
    if (listLength(args->fragments) != 1) {
        sds raw_bytes_ptr = sdsMakeRoomFor(sdsempty(), args->total_bytes);
        while (listLength(args->fragments) != 0) {
            listNode* head = listFirst(args->fragments);
            raw_bytes_ptr =
                sdscatsds(raw_bytes_ptr, ((robj*)listNodeValue(head))->ptr);
            decrRefCount(listNodeValue(head));
            listDelNode(args->fragments, head);
        }
        args->raw_bytes = createObject(OBJ_STRING, raw_bytes_ptr);
    } else {
        listNode* head = listFirst(args->fragments);
        incrRefCount(listNodeValue(head));
        args->raw_bytes = listNodeValue(head);
    }

    void* ptr = args->raw_bytes->ptr;
    if (verifyDumpPayload(ptr, sdslen(ptr)) != C_OK) {
        args->errmsg =
            sdscatfmt(sdsempty(), "DUMP payload version or checksum are wrong");
        return 0;
    }

    rio payload;
    rioInitWithBuffer(&payload, ptr);

    int type = rdbLoadObjectType(&payload);
    if (type == -1) {
        args->errmsg =
            sdscatfmt(sdsempty(), "Bad data format, invalid object type.");
        return 0;
    }
    args->obj = rdbLoadObject(type, &payload);
    if (args->obj == NULL) {
        args->errmsg =
            sdscatfmt(sdsempty(), "Bad data format, invalid object data.");
        return 0;
    }
    return 1;
}

static void restoreGenericCommandPropagateRestore(restoreCommandArgs* args);

static void restoreGenericCommandReplyAndPropagate(restoreCommandArgs* args) {
    client* c = args->client;
    if (args->errmsg != NULL) {
        if (c != NULL) {
            addReplyError(c, args->errmsg);
        }
        return;
    }

    int overwrite = lookupKeyWrite(args->db, args->key) != NULL;
    if (overwrite && !args->replace) {
        if (c != NULL) {
            addReply(c, shared.busykeyerr);
        }
        return;
    }
    if (c != NULL) {
        addReply(c, shared.ok);
    }

    if (overwrite) {
        dbDelete(args->db, args->key);
    }
    incrRefCount(args->obj);
    dbAdd(args->db, args->key, args->obj);

    if (args->ttl != 0) {
        setExpire(c, args->db, args->key, mstime() + args->ttl);
    }
    signalModifiedKey(args->db, args->key);
    server.dirty++;

    // TODO Forward RESTORE-ASYNC for non-blocking migration.

    restoreGenericCommandPropagateRestore(args);
}

// RESTORE key ttl serialized-value REPLACE
static void restoreGenericCommandPropagateRestore(restoreCommandArgs* args) {
    robj* propargv[5];
    propargv[0] = createStringObject("RESTORE", 7);
    propargv[1] = args->key;
    incrRefCount(propargv[1]);
    propargv[2] = createStringObjectFromLongLong(args->ttl);
    propargv[3] = args->raw_bytes;
    incrRefCount(propargv[3]);
    propargv[4] = createStringObject("REPLACE", 7);

    int propargc = sizeof(propargv) / sizeof(propargv[0]);

    propagate(server.restoreCommand, args->db->id, propargv, propargc,
              PROPAGATE_AOF | PROPAGATE_REPL);

    for (int i = 0; i < propargc; i++) {
        decrRefCount(propargv[i]);
    }
}

// RESTORE-ASYNC key PREPARE
// RESTORE-ASYNC key PAYLOAD serialized-fragment
// RESTORE-ASYNC key RESTORE ttl [REPLACE]
void restoreAsyncCommand(client* c) {
    robj* key = c->argv[1];
    robj* cmd = c->argv[2];
    UNUSED(key);
    UNUSED(cmd);
    UNUSED(c);
    // TODO
    serverPanic("TODO");
}

// RESTORE key ttl serialized-value [REPLACE]
void restoreCommand(client* c) {
    int replace = 0;
    for (int j = 4; j < c->argc; j++) {
        if (strcasecmp(c->argv[j]->ptr, "REPLACE") == 0) {
            replace = 1;
        } else {
            addReply(c, shared.syntaxerr);
            return;
        }
    }

    long long ttl;
    if (getLongLongFromObjectOrReply(c, c->argv[2], &ttl, NULL) != C_OK) {
        return;
    } else if (ttl < 0) {
        addReplyError(c, "Invalid TTL value, must be >= 0");
        return;
    }
    serverAssert(c->restore_command_args == NULL);

    restoreCommandArgs* args =
        initRestoreCommandArgs(c, c->argv[1], ttl, replace, 0);

    incrRefCount(c->argv[3]);
    listAddNodeTail(args->fragments, c->argv[3]);
    args->total_bytes += sdslen(c->argv[3]->ptr);

    restoreGenericCommandExtractPayload(args);

    restoreGenericCommandReplyAndPropagate(args);

    freeRestoreCommandArgs(args);
}

/* ---------------- TODO ---------------------------------------------------- */

void migrateBackgroundThread(void) {}
void migrateCommand(client* c) { UNUSED(c); }
void migrateAsyncCommand(client* c) { UNUSED(c); }
void unblockClientFromMigrate(client* c) { UNUSED(c); }
void unblockClientFromRestore(client* c) { UNUSED(c); }
void freeMigrateCommandArgsFromFreeClient(client* c) { UNUSED(c); }
void freeRestoreCommandArgsFromFreeClient(client* c) { UNUSED(c); }
void migrateCloseTimedoutSockets(void) {}
void restoreCloseTimedoutCommands(void) {}
