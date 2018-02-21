#include "server.h"

extern void decrRefCountLazyfree(robj* obj);

// ---------------- MIGRATE CACHED SOCKET ----------------------------------- //

#define MIGRATE_SOCKET_CACHE_ITEMS 64
#define MIGRATE_SOCKET_CACHE_TTL 10

typedef struct {
    int fd;
    int last_dbid;
    time_t last_use_time;
    const char* name;
    int inuse;
    int error;
    int authenticated;
} migrateCachedSocket;

static sds migrateSocketName(robj* host, robj* port, robj* auth) {
    sds name = sdscatfmt(sdsempty(), "%S:%S#", host->ptr, port->ptr);
    if (auth == NULL) {
        return name;
    }
    return sdscatsds(name, auth->ptr);
}

static void migrateCloseSocket(migrateCachedSocket* cs) {
    dictDelete(server.migrate_cached_sockets, cs->name);
    close(cs->fd);
    zfree(cs);
}

void migrateCloseTimedoutSockets(void) {
    dictIterator* di = dictGetSafeIterator(server.migrate_cached_sockets);
    dictEntry* entry;
    while ((entry = dictNext(di)) != NULL) {
        migrateCachedSocket* cs = dictGetVal(entry);
        if (cs->inuse ||
            server.unixtime - cs->last_use_time <= MIGRATE_SOCKET_CACHE_TTL) {
            continue;
        }
        migrateCloseSocket(cs);
    }
    dictReleaseIterator(di);
}

static migrateCachedSocket* migrateGetSocketOrReply(client* c, robj* host,
                                                    robj* port, robj* auth,
                                                    mstime_t timeout) {
    sds name = migrateSocketName(host, port, auth);
    migrateCachedSocket* cs =
        dictFetchValue(server.migrate_cached_sockets, name);
    if (cs != NULL) {
        sdsfree(name);
        if (!cs->inuse) {
            return cs;
        }
        addReplySds(
            c, sdscatfmt(sdsempty(), "-RETRYLATER target %S:%S is busy.\r\n",
                         host->ptr, port->ptr));
        return NULL;
    }

    if (dictSize(server.migrate_cached_sockets) == MIGRATE_SOCKET_CACHE_ITEMS) {
        dictEntry* entry = dictGetRandomKey(server.migrate_cached_sockets);
        migrateCloseSocket(dictGetVal(entry));
    }

    int fd = anetTcpNonBlockConnect(server.neterr, host->ptr, atoi(port->ptr));
    if (fd == -1) {
        sdsfree(name);
        addReplyErrorFormat(c, "Can't connect to target node: '%s'.",
                            server.neterr);
        return NULL;
    }
    anetEnableTcpNoDelay(server.neterr, fd);

    if ((aeWait(fd, AE_WRITABLE, timeout) & AE_WRITABLE) == 0) {
        sdsfree(name);
        addReplySds(
            c, sdsnew("-IOERR error or timeout connecting to the client.\r\n"));
        close(fd);
        return NULL;
    }

    cs = zmalloc(sizeof(*cs));
    cs->fd = fd;
    cs->last_dbid = -1;
    cs->last_use_time = server.unixtime;
    cs->name = name;
    cs->inuse = 0;
    cs->error = 0;
    cs->authenticated = 0;
    dictAdd(server.migrate_cached_sockets, name, cs);
    return cs;
}

#define SYNC_WRITE_IOBUF_LEN (64 * 1024)

static int syncWriteBuffer(int fd, sds buffer, mstime_t timeout) {
    ssize_t pos = 0, towrite, written;
    while ((towrite = sdslen(buffer) - pos) > 0) {
        towrite =
            (towrite > SYNC_WRITE_IOBUF_LEN ? SYNC_WRITE_IOBUF_LEN : towrite);
        written = syncWrite(fd, buffer + pos, towrite, timeout);
        if (written != towrite) {
            return C_ERR;
        }
        pos += written;
    }
    return C_OK;
}

static sds syncAuthCommand(int fd, mstime_t timeout, sds password) {
    rio cmd;
    rioInitWithBuffer(&cmd, sdsempty());

    const char* cmd_name = "AUTH";
    serverAssert(rioWriteBulkCount(&cmd, '*', 2));
    serverAssert(rioWriteBulkString(&cmd, cmd_name, strlen(cmd_name)));
    serverAssert(rioWriteBulkString(&cmd, password, sdslen(password)));

    if (syncWriteBuffer(fd, cmd.io.buffer.ptr, timeout) != C_OK) {
        sdsfree(cmd.io.buffer.ptr);
        return sdscatfmt(sdsempty(), "Command %s failed, sending error '%s'.",
                         cmd_name, strerror(errno));
    }
    sdsfree(cmd.io.buffer.ptr);

    char buf[1024];
    if (syncReadLine(fd, buf, sizeof(buf), timeout) <= 0) {
        return sdscatfmt(sdsempty(), "Command %s failed, reading error '%s'.",
                         cmd_name, strerror(errno));
    }
    return buf[0] != '+'
               ? sdscatfmt(sdsempty(), "Command %s failed, target replied: %s",
                           cmd_name, buf)
               : NULL;
}

static sds syncPingCommand(int fd, mstime_t timeout) {
    rio cmd;
    rioInitWithBuffer(&cmd, sdsempty());

    const char* cmd_name = "PING";
    serverAssert(rioWriteBulkCount(&cmd, '*', 1));
    serverAssert(rioWriteBulkString(&cmd, cmd_name, strlen(cmd_name)));

    if (syncWriteBuffer(fd, cmd.io.buffer.ptr, timeout) != C_OK) {
        sdsfree(cmd.io.buffer.ptr);
        return sdscatfmt(sdsempty(), "Command %s failed, sending error '%s'.",
                         cmd_name, strerror(errno));
    }
    sdsfree(cmd.io.buffer.ptr);

    char buf[1024];
    if (syncReadLine(fd, buf, sizeof(buf), timeout) <= 0) {
        return sdscatfmt(sdsempty(), "Command %s failed, reading error '%s'.",
                         cmd_name, strerror(errno));
    }
    return buf[0] != '+'
               ? sdscatfmt(sdsempty(), "Command %s failed, target replied: %s",
                           cmd_name, buf)
               : NULL;
}

static sds syncSelectCommand(int fd, mstime_t timeout, int dbid) {
    rio cmd;
    rioInitWithBuffer(&cmd, sdsempty());

    const char* cmd_name = "SELECT";
    serverAssert(rioWriteBulkCount(&cmd, '*', 2));
    serverAssert(rioWriteBulkString(&cmd, cmd_name, strlen(cmd_name)));
    serverAssert(rioWriteBulkLongLong(&cmd, dbid));

    if (syncWriteBuffer(fd, cmd.io.buffer.ptr, timeout) != C_OK) {
        sdsfree(cmd.io.buffer.ptr);
        return sdscatfmt(sdsempty(), "Command %s failed, sending error '%s'.",
                         cmd_name, strerror(errno));
    }
    sdsfree(cmd.io.buffer.ptr);

    char buf[1024];
    if (syncReadLine(fd, buf, sizeof(buf), timeout) <= 0) {
        return sdscatfmt(sdsempty(), "Command %s failed, reading error '%s'.",
                         cmd_name, strerror(errno));
    }
    return buf[0] != '+'
               ? sdscatfmt(sdsempty(), "Command %s failed, target replied: %s",
                           cmd_name, buf)
               : NULL;
}

// ---------------- MIGRATE / MIGRATE-ASYNC --------------------------------- //

struct _migrateCommandArgs {
    redisDb* db;
    robj* host;
    robj* port;
    robj* auth;
    int dbid;
    int copy, replace;
    int num_keys;
    int non_blocking;
    mstime_t timeout;

    struct {
        robj* key;
        robj* obj;
        mstime_t expireat;
        int pending;
        int success;
    } * kvpairs;

    migrateCachedSocket* socket;
    sds errmsg;

    const char* cmd_name;

    client* client;
};

static void freeMigrateCommandArgs(migrateCommandArgs* args) {
    if (args->host != NULL) {
        decrRefCount(args->host);
    }
    if (args->port != NULL) {
        decrRefCount(args->port);
    }
    if (args->auth != NULL) {
        decrRefCount(args->auth);
    }
    if (args->kvpairs != NULL) {
        for (int j = 0; j < args->num_keys; j++) {
            robj* key = args->kvpairs[j].key;
            robj* obj = args->kvpairs[j].obj;
            decrRefCount(key);
            decrRefCountLazyfree(obj);
        }
        zfree(args->kvpairs);
    }
    if (args->socket != NULL) {
        if (args->socket->error) {
            migrateCloseSocket(args->socket);
        } else {
            args->socket->inuse = 0;
        }
    }
    if (args->errmsg != NULL) {
        sdsfree(args->errmsg);
    }
    zfree(args);
}

// MIGRATE       host port key dbid timeout [COPY | REPLACE | AUTH password]
// MIGRATE-ASYNC host port key dbid timeout [COPY | REPLACE | AUTH password]
//
// MIGRATE       host port ""  dbid timeout [COPY | REPLACE | AUTH password]
//               KEYS key1 key2 ... keyN
// MIGRATE-ASYNC host port ""  dbid timeout [COPY | REPLACE | AUTH password]
//               KEYS key1 key2 ... keyN
static migrateCommandArgs* initMigrateCommandArgsOrReply(client* c,
                                                         int non_blocking) {
    migrateCommandArgs* args = zcalloc(sizeof(*args));
    int num_keys = 1, first_key = 3;
    for (int j = 6; j < c->argc; j++) {
        int moreargs = (j != c->argc - 1);
        if (strcasecmp(c->argv[j]->ptr, "copy") == 0) {
            args->copy = 1;
        } else if (strcasecmp(c->argv[j]->ptr, "replace") == 0) {
            args->replace = 1;
        } else if (strcasecmp(c->argv[j]->ptr, "auth") == 0) {
            if (!moreargs) {
                addReply(c, shared.syntaxerr);
                goto failed_cleanup;
            }
            j++;
            args->auth = c->argv[j];
            incrRefCount(args->auth);
        } else if (strcasecmp(c->argv[j]->ptr, "keys") == 0) {
            if (sdslen(c->argv[3]->ptr) != 0) {
                addReplyError(c,
                              "When using MIGRATE KEYS option, the key argument"
                              " must be set to the empty string");
                goto failed_cleanup;
            }
            first_key = j + 1;
            num_keys = c->argc - j - 1;
            goto parsed_options;
        } else {
            addReply(c, shared.syntaxerr);
            goto failed_cleanup;
        }
    }

parsed_options:
    args->non_blocking = non_blocking;

    args->host = c->argv[1];
    incrRefCount(args->host);

    args->port = c->argv[2];
    incrRefCount(args->port);

    long dbid, timeout;
    if (getLongFromObjectOrReply(c, c->argv[5], &timeout, NULL) != C_OK ||
        getLongFromObjectOrReply(c, c->argv[4], &dbid, NULL) != C_OK) {
        goto failed_cleanup;
    }

    args->dbid = (int)dbid;
    args->timeout = (timeout <= 0) ? 1000 : timeout;

    args->kvpairs = zmalloc(sizeof(args->kvpairs[0]) * num_keys);

    for (int i = 0; i < num_keys; i++) {
        robj* key = c->argv[first_key + i];
        robj* obj = lookupKeyRead(c->db, key);
        if (obj == NULL) {
            continue;
        }
        int j = args->num_keys++;
        args->kvpairs[j].key = key;
        args->kvpairs[j].obj = obj;
        args->kvpairs[j].expireat = getExpire(c->db, key);
        incrRefCount(key);
        incrRefCount(obj);
    }

    if (args->num_keys == 0) {
        addReplySds(c, sdsnew("+NOKEY\r\n"));
        goto failed_cleanup;
    }
    migrateCachedSocket* cs = migrateGetSocketOrReply(
        c, args->host, args->port, args->auth, args->timeout);
    if (cs == NULL) {
        goto failed_cleanup;
    }
    serverAssert(!cs->inuse && !cs->error);

    args->socket = cs;
    args->socket->inuse = 1;
    args->socket->last_use_time = server.unixtime;

    args->db = c->db;
    args->cmd_name = args->non_blocking ? "MIGRATE-ASYNC" : "MIGRATE";
    args->client = c;
    return args;

failed_cleanup:
    freeMigrateCommandArgs(args);
    return NULL;
}

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

    const char* cmd_name;

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
    args->last_update_time = server.unixtime;
    if (server.cluster_enabled) {
        args->cmd_name =
            non_blocking ? "RESTORE-ASYNC-ASKING" : "RESTORE-ASKING";
    } else {
        args->cmd_name = non_blocking ? "RESTORE-ASYNC" : "RESTORE";
    }
    args->client = c;
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
void restoreCloseTimedoutCommands(void) {}
