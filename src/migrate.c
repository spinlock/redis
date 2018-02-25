#include "server.h"

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

// ---------------- MIGRATE RIO COMMAND ------------------------------------- //

typedef struct {
    rio rio;
    sds payload;
    mstime_t timeout;
    int replace;
    int non_blocking;
    int num_requests;
    struct {
        robj* key;
        mstime_t ttl;
    } privdata;
    struct {
        int fd;
        sds buffer_ptr;
    } io;
} rioMigrateCommand;

#define RIO_GOTO_IF_ERROR(e)         \
    do {                             \
        if (!(e)) {                  \
            goto rio_failed_cleanup; \
        }                            \
    } while (0)

#define RIO_MAX_IOBUF_LEN (64LL * 1024 * 1024)

static int rioMigrateCommandFlushIOBuffer(rioMigrateCommand* cmd, int force) {
    if (!force && sdslen(cmd->io.buffer_ptr) < RIO_MAX_IOBUF_LEN) {
        return 1;
    }
    if (syncWriteBuffer(cmd->io.fd, cmd->io.buffer_ptr, cmd->timeout) != C_OK) {
        return 0;
    }
    sdsclear(cmd->io.buffer_ptr);
    return 1;
}

static int rioMigrateCommandNonBlockingFragment(rioMigrateCommand* cmd) {
    rio _rio;
    rio* rio = &_rio;
    rioInitWithBuffer(rio, cmd->io.buffer_ptr);

    robj* key = cmd->privdata.key;
    const char* cmd_name =
        server.cluster_enabled ? "RESTORE-ASYNC-ASKING" : "RESTORE-ASYNC";

    if (cmd->num_requests != 0) {
        goto rio_fragment_payload;
    }
    RIO_GOTO_IF_ERROR(rioWriteBulkCount(rio, '*', 2));
    RIO_GOTO_IF_ERROR(rioWriteBulkString(rio, cmd_name, strlen(cmd_name)));
    RIO_GOTO_IF_ERROR(rioWriteBulkString(rio, "RESET", 5));
    cmd->num_requests++;

rio_fragment_payload:
    RIO_GOTO_IF_ERROR(rioWriteBulkCount(rio, '*', 4));
    RIO_GOTO_IF_ERROR(rioWriteBulkString(rio, cmd_name, strlen(cmd_name)));
    RIO_GOTO_IF_ERROR(rioWriteBulkString(rio, "PAYLOAD", 7));
    RIO_GOTO_IF_ERROR(rioWriteBulkString(rio, key->ptr, sdslen(key->ptr)));
    RIO_GOTO_IF_ERROR(
        rioWriteBulkString(rio, cmd->payload, sdslen(cmd->payload)));
    cmd->num_requests++;

    sdsclear(cmd->payload);
    cmd->io.buffer_ptr = rio->io.buffer.ptr;
    return rioMigrateCommandFlushIOBuffer(cmd, 0);

rio_failed_cleanup:
    cmd->io.buffer_ptr = rio->io.buffer.ptr;
    return 0;
}

static size_t rioMigrateObjectRead(rio* r, void* buf, size_t len) {
    UNUSED(r);
    UNUSED(buf);
    UNUSED(len);
    serverPanic("Unsupported operation.");
}

static off_t rioMigrateObjectTell(rio* r) {
    UNUSED(r);
    serverPanic("Unsupported operation.");
}

#define RIO_MIGRATE_COMMAND(r) \
    ((rioMigrateCommand*)((char*)(r)-offsetof(rioMigrateCommand, rio)))

static int rioMigrateObjectFlush(rio* r) {
    rioMigrateCommand* cmd = RIO_MIGRATE_COMMAND(r);

    rio _rio;
    rio* rio = &_rio;
    rioInitWithBuffer(rio, cmd->io.buffer_ptr);

    robj* key = cmd->privdata.key;
    mstime_t ttl = cmd->privdata.ttl;

    if (!cmd->non_blocking) {
        const char* cmd_name =
            server.cluster_enabled ? "RESTORE-ASKING" : "RESTORE";
        RIO_GOTO_IF_ERROR(rioWriteBulkCount(rio, '*', cmd->replace ? 5 : 4));
        RIO_GOTO_IF_ERROR(rioWriteBulkString(rio, cmd_name, strlen(cmd_name)));
        RIO_GOTO_IF_ERROR(rioWriteBulkString(rio, key->ptr, sdslen(key->ptr)));
        RIO_GOTO_IF_ERROR(rioWriteBulkLongLong(rio, ttl));
        RIO_GOTO_IF_ERROR(
            rioWriteBulkString(rio, cmd->payload, sdslen(cmd->payload)));
        if (cmd->replace) {
            RIO_GOTO_IF_ERROR(rioWriteBulkString(rio, "REPLACE", 7));
        }
        sdsclear(cmd->payload);
        serverAssert(cmd->num_requests == 0);
    } else {
        if (sdslen(cmd->payload) != 0 &&
            !rioMigrateCommandNonBlockingFragment(cmd)) {
            goto rio_failed_cleanup;
        }
        const char* cmd_name =
            server.cluster_enabled ? "RESTORE-ASYNC-ASKING" : "RESTORE-ASYNC";
        RIO_GOTO_IF_ERROR(rioWriteBulkCount(rio, '*', cmd->replace ? 5 : 4));
        RIO_GOTO_IF_ERROR(rioWriteBulkString(rio, cmd_name, strlen(cmd_name)));
        RIO_GOTO_IF_ERROR(rioWriteBulkString(rio, "RESTORE", 7));
        RIO_GOTO_IF_ERROR(rioWriteBulkString(rio, key->ptr, sdslen(key->ptr)));
        RIO_GOTO_IF_ERROR(rioWriteBulkLongLong(rio, ttl));
        if (cmd->replace) {
            RIO_GOTO_IF_ERROR(rioWriteBulkString(rio, "REPLACE", 7));
        }
        serverAssert(cmd->num_requests >= 2);
    }

    cmd->num_requests++;
    cmd->io.buffer_ptr = rio->io.buffer.ptr;
    return rioMigrateCommandFlushIOBuffer(cmd, 0);

rio_failed_cleanup:
    cmd->io.buffer_ptr = rio->io.buffer.ptr;
    return 0;
}

static size_t rioMigrateObjectWrite(rio* r, const void* buf, size_t len) {
    rioMigrateCommand* cmd = RIO_MIGRATE_COMMAND(r);
    cmd->payload = sdscatlen(cmd->payload, buf, len);
    if (!cmd->non_blocking) {
        return 1;
    }
    if (sdslen(cmd->payload) < RIO_MAX_IOBUF_LEN) {
        return 1;
    }
    return rioMigrateCommandNonBlockingFragment(cmd);
}

static const rio rioMigrateObjectIO = {
    .read = rioMigrateObjectRead,
    .tell = rioMigrateObjectTell,
    .flush = rioMigrateObjectFlush,
    .write = rioMigrateObjectWrite,
    .update_cksum = rioGenericUpdateChecksum,
};

static int rioMigrateCommandObject(rioMigrateCommand* cmd, robj* key, robj* obj,
                                   mstime_t ttl) {
    rio* rio = &cmd->rio;
    rio->cksum = 0;

    cmd->num_requests = 0;
    cmd->privdata.key = key;
    cmd->privdata.ttl = ttl;

    RIO_GOTO_IF_ERROR(rdbSaveObjectType(rio, obj));
    RIO_GOTO_IF_ERROR(rdbSaveObject(rio, obj));

    uint16_t ver = RDB_VERSION;
    memrev64ifbe(&ver);
    RIO_GOTO_IF_ERROR(rioWrite(rio, &ver, sizeof(ver)));

    uint64_t crc = rio->cksum;
    memrev64ifbe(&crc);
    RIO_GOTO_IF_ERROR(rioWrite(rio, &crc, sizeof(crc)));

    RIO_GOTO_IF_ERROR(rioFlush(rio));
    return 1;

rio_failed_cleanup:
    return 0;
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
    int processing;
};

extern void decrRefCountLazyfree(robj* obj);

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

static int migrateGenericCommandSendRequests(migrateCommandArgs* args) {
    migrateCachedSocket* cs = args->socket;
    if (!cs->authenticated) {
        if (args->auth != NULL) {
            args->errmsg =
                syncAuthCommand(cs->fd, args->timeout, args->auth->ptr);
        } else {
            args->errmsg = syncPingCommand(cs->fd, args->timeout);
        }
        if (args->errmsg != NULL) {
            goto failed_socket_error;
        }
        cs->authenticated = 1;
    }
    if (cs->last_dbid != args->dbid) {
        args->errmsg = syncSelectCommand(cs->fd, args->dbid, args->timeout);
        if (args->errmsg != NULL) {
            goto failed_socket_error;
        }
        cs->last_dbid = args->dbid;
    }

    rioMigrateCommand _cmd = {
        .rio = rioMigrateObjectIO,
        .payload = sdsempty(),
        .timeout = args->timeout,
        .replace = args->replace,
        .non_blocking = args->non_blocking,
        .io = {.fd = cs->fd, .buffer_ptr = sdsempty()},
    };
    rioMigrateCommand* cmd = &_cmd;

    for (int j = 0; j < args->num_keys; j++) {
        robj* key = args->kvpairs[j].key;
        robj* obj = args->kvpairs[j].obj;
        mstime_t ttl = 0;
        mstime_t expireat = args->kvpairs[j].expireat;
        if (expireat != -1) {
            ttl = expireat - mstime();
            ttl = (ttl < 1) ? 1 : ttl;
        }
        RIO_GOTO_IF_ERROR(rioMigrateCommandObject(cmd, key, obj, ttl));

        args->kvpairs[j].pending = cmd->num_requests;
    }
    RIO_GOTO_IF_ERROR(rioMigrateCommandFlushIOBuffer(cmd, 1));

    sdsfree(cmd->payload);
    sdsfree(cmd->io.buffer_ptr);

    args->socket->last_use_time = server.unixtime;
    return 1;

rio_failed_cleanup:
    sdsfree(cmd->payload);
    sdsfree(cmd->io.buffer_ptr);

    args->errmsg =
        sdscatfmt(sdsempty(), "Command %s failed, sending error '%s'.",
                  args->cmd_name, strerror(errno));

failed_socket_error:
    args->socket->error = 1;
    return 0;
}

static int migrateGenericCommandFetchReplies(migrateCommandArgs* args) {
    migrateCachedSocket* cs = args->socket;
    for (int j = 0; j < args->num_keys; j++) {
        int errors = 0;
        for (int i = 0; i < args->kvpairs[j].pending; i++) {
            char buf[1024];
            if (syncReadLine(cs->fd, buf, sizeof(buf), args->timeout) <= 0) {
                goto failed_socket_error;
            }
            if (buf[0] == '+') {
                continue;
            }
            errors++;
            if (args->errmsg != NULL) {
                continue;
            }
            args->errmsg =
                sdscatfmt(sdsempty(), "Command %s failed, target replied: %s",
                          args->cmd_name, buf);
        }
        if (errors == 0) {
            args->kvpairs[j].success = 1;
        }
    }

    args->socket->last_use_time = server.unixtime;
    return 1;

failed_socket_error:
    if (args->errmsg != NULL) {
        sdsfree(args->errmsg);
    }
    args->errmsg =
        sdscatfmt(sdsempty(), "Command %s failed, reading error '%s'.",
                  args->cmd_name, strerror(errno));

    args->socket->error = 1;
    return 0;
}

static void migrateGenericCommandReplyAndPropagate(migrateCommandArgs* args) {
    client* c = args->client;
    if (c != NULL) {
        if (args->errmsg != NULL) {
            addReplyError(c, args->errmsg);
        } else {
            addReply(c, shared.ok);
        }
    }
    if (args->copy) {
        return;
    }

    robj** propargv = zmalloc(sizeof(propargv[0]) * (1 + args->num_keys));
    int migrated = 0;
    for (int j = 0; j < args->num_keys; j++) {
        if (!args->kvpairs[j].success) {
            continue;
        }
        migrated++;

        robj* key = args->kvpairs[j].key;
        propargv[migrated] = key;

        dbDelete(args->db, key);
        signalModifiedKey(args->db, key);
        server.dirty++;
    }

    if (migrated == 0) {
        zfree(propargv);
        return;
    }
    if (c != NULL && !args->non_blocking) {
        preventCommandPropagation(c);
    }

    propargv[0] = createStringObject("DEL", 3);

    propagate(server.delCommand, args->db->id, propargv, 1 + migrated,
              PROPAGATE_AOF | PROPAGATE_REPL);

    decrRefCount(propargv[0]);
    zfree(propargv);
}

void migrateCommand(client* c) {
    migrateCommandArgs* args = initMigrateCommandArgsOrReply(c, 0);
    if (args == NULL) {
        return;
    }
    serverAssert(c->migrate_command_args == NULL);

    if (migrateGenericCommandSendRequests(args)) {
        migrateGenericCommandFetchReplies(args);
    }
    migrateGenericCommandReplyAndPropagate(args);

    freeMigrateCommandArgs(args);
}

static void migrateAsyncCommandCallback(migrateCommandArgs* args) {
    serverAssert(args->client == NULL ||
                 args->client->migrate_command_args == args);

    dict* locked_keys = args->db->migrate_locked_keys;
    for (int j = 0; j < args->num_keys; j++) {
        robj* key = args->kvpairs[j].key;
        serverAssert(dictDelete(locked_keys, key) == DICT_OK);
    }
    migrateGenericCommandReplyAndPropagate(args);

    client* c = args->client;
    if (c != NULL) {
        unblockClient(c);
    }
    serverAssert(c->migrate_command_args == NULL);

    freeMigrateCommandArgs(args);
}

static void migrateCommandThreadAddMigrateJobTail(migrateCommandArgs* args);

void migrateAsyncCommand(client* c) {
    migrateCommandArgs* args = initMigrateCommandArgsOrReply(c, 1);
    if (args == NULL) {
        return;
    }
    serverAssert(c->migrate_command_args == NULL);

    dict* locked_keys = args->db->migrate_locked_keys;
    for (int j = 0; j < args->num_keys; j++) {
        robj* key = args->kvpairs[j].key;
        incrRefCount(key);
        serverAssert(dictAdd(locked_keys, key, NULL) == DICT_OK);
    }
    c->migrate_command_args = args;

    migrateCommandThreadAddMigrateJobTail(args);

    blockClient(c, BLOCKED_MIGRATE);
}

void unblockClientFromMigrate(client* c) {
    serverAssert(c->migrate_command_args != NULL &&
                 c->migrate_command_args->client == c);
    c->migrate_command_args->client = NULL;
    c->migrate_command_args = NULL;
}

void freeMigrateCommandArgsFromFreeClient(client* c) {
    UNUSED(c);
    serverPanic("Should not arrive here.");
}

static int isLockedByMigrateAsyncCommand(redisDb* db, robj* key) {
    return dictFind(db->migrate_locked_keys, key) != NULL;
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

    robj* payload;

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

    if (args->payload != NULL) {
        decrRefCount(args->payload);
    }
    if (args->errmsg != NULL) {
        sdsfree(args->errmsg);
    }
    zfree(args);
}

static restoreCommandArgs* initRestoreCommandArgs(client* c, robj* key,
                                                  int non_blocking) {
    restoreCommandArgs* args = zcalloc(sizeof(*args));
    args->db = c->db;
    args->key = key;
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
        sds payload_ptr = sdsMakeRoomFor(sdsempty(), args->total_bytes);
        while (listLength(args->fragments) != 0) {
            listNode* head = listFirst(args->fragments);
            payload_ptr =
                sdscatsds(payload_ptr, ((robj*)listNodeValue(head))->ptr);
            decrRefCount(listNodeValue(head));
            listDelNode(args->fragments, head);
        }
        args->payload = createObject(OBJ_STRING, payload_ptr);
    } else {
        listNode* head = listFirst(args->fragments);
        incrRefCount(listNodeValue(head));
        args->payload = listNodeValue(head);
    }

    void* ptr = args->payload->ptr;
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

static void restoreGenericCommandReplyAndPropagate(restoreCommandArgs* args) {
    client* c = args->client;
    if (args->errmsg != NULL) {
        if (c != NULL) {
            addReplyError(c, args->errmsg);
        }
        return;
    }

    if (isLockedByMigrateAsyncCommand(args->db, args->key)) {
        if (c != NULL) {
            addReplySds(c, sdscatfmt(sdsempty(), "-RETRYLATER %S is busy.\r\n",
                                     args->key->ptr));
        }
        return;
    }

    int overwrite = lookupKeyWrite(args->db, args->key) != NULL;
    if (overwrite) {
        if (!args->replace) {
            if (c != NULL) {
                addReply(c, shared.busykeyerr);
            }
            return;
        }
        dbDelete(args->db, args->key);
    }
    incrRefCount(args->obj);
    dbAdd(args->db, args->key, args->obj);

    if (args->ttl != 0) {
        setExpire(c, args->db, args->key, mstime() + args->ttl);
    }
    signalModifiedKey(args->db, args->key);
    server.dirty++;

    if (c != NULL) {
        addReply(c, shared.ok);
    }
    if (c != NULL && !args->non_blocking) {
        preventCommandPropagation(c);
    }

    // RESTORE key ttl serialized-value REPLACE [ASYNC]
    robj* propargv[6];
    propargv[0] = createStringObject("RESTORE", 7);
    propargv[1] = args->key;
    incrRefCount(propargv[1]);
    propargv[2] = createStringObjectFromLongLong(args->ttl);
    propargv[3] = args->payload;
    incrRefCount(propargv[3]);
    propargv[4] = createStringObject("REPLACE", 7);

    int propargc = sizeof(propargv) / sizeof(propargv[0]) - 1;
    if (args->non_blocking) {
        propargv[5] = createStringObject("ASYNC", 5);
        propargc++;
    }

    propagate(server.restoreCommand, args->db->id, propargv, propargc,
              PROPAGATE_AOF | PROPAGATE_REPL);

    for (int i = 0; i < propargc; i++) {
        decrRefCount(propargv[i]);
    }
}

static void restoreCommandByCommandArgs(client* c, restoreCommandArgs* args) {
    serverAssert(c->restore_command_args == NULL);

    restoreGenericCommandExtractPayload(args);

    restoreGenericCommandReplyAndPropagate(args);

    freeRestoreCommandArgs(args);
}

static void restoreAsyncCommandCallback(restoreCommandArgs* args) {
    serverAssert(args->client == NULL ||
                 args->client->restore_command_args == args);

    restoreGenericCommandReplyAndPropagate(args);

    client* c = args->client;
    if (c != NULL) {
        unblockClient(c);
    }
    serverAssert(c->restore_command_args == NULL);

    freeRestoreCommandArgs(args);
}

static void migrateCommandThreadAddRestoreJobTail(restoreCommandArgs* args);

static void restoreAsyncCommandByCommandArgs(client* c,
                                             restoreCommandArgs* args,
                                             mstime_t ttl, int replace) {
    if (args != NULL) {
        serverAssert(c->restore_command_args == NULL);
        c->restore_command_args = args;
    } else {
        serverAssert(c->restore_command_args != NULL);
        args = c->restore_command_args;
    }
    args->ttl = ttl, args->replace = replace;

    migrateCommandThreadAddRestoreJobTail(args);

    blockClient(c, BLOCKED_RESTORE);
}

static void restoreAsyncCommandResetIfNeeded(client* c) {
    restoreCommandArgs* args = c->restore_command_args;
    if (c->restore_command_args == NULL) {
        return;
    }
    serverAssert(!args->processing);

    c->restore_command_args = NULL;

    freeRestoreCommandArgs(args);
}

// RESTORE-ASYNC RESET
// RESTORE-ASYNC PAYLOAD key serialized-fragment
// RESTORE-ASYNC RESTORE key ttl [REPLACE]
void restoreAsyncCommand(client* c) {
    // RESTORE-ASYNC RESET
    if (strcasecmp(c->argv[1]->ptr, "RESET") == 0) {
        if (c->argc != 2) {
            goto failed_syntax_error;
        }
        restoreAsyncCommandResetIfNeeded(c);
        addReply(c, shared.ok);
        return;
    }

    // RESTORE-ASYNC PAYLOAD key serialized-fragment
    if (strcasecmp(c->argv[1]->ptr, "PAYLOAD") == 0) {
        if (c->argc != 4) {
            goto failed_syntax_error;
        }
        if (c->restore_command_args == NULL) {
            c->restore_command_args = initRestoreCommandArgs(c, c->argv[2], 1);
        } else if (compareStringObjects(c->argv[2],
                                        c->restore_command_args->key) != 0) {
            goto failed_syntax_error;
        }
        restoreCommandArgs* args = c->restore_command_args;

        incrRefCount(c->argv[3]);
        listAddNodeTail(args->fragments, c->argv[3]);
        args->total_bytes += sdslen(c->argv[3]->ptr);

        addReply(c, shared.ok);
        return;
    }

    // RESTORE-ASYNC RESTORE key ttl [REPLACE]
    if (strcasecmp(c->argv[1]->ptr, "RESTORE") == 0) {
        if (c->argc < 4) {
            goto failed_syntax_error;
        }
        int replace = 0;
        for (int j = 4; j < c->argc; j++) {
            if (strcasecmp(c->argv[j]->ptr, "REPLACE") == 0) {
                replace = 1;
            } else {
                goto failed_syntax_error;
            }
        }

        long long ttl;
        if (getLongLongFromObjectOrReply(c, c->argv[3], &ttl, NULL) != C_OK) {
            return;
        } else if (ttl < 0) {
            addReplyError(c, "Invalid TTL value, must be >= 0");
            return;
        }

        if (c->restore_command_args == NULL) {
            goto failed_syntax_error;
        } else if (compareStringObjects(c->argv[2],
                                        c->restore_command_args->key) != 0) {
            goto failed_syntax_error;
        }

        restoreAsyncCommandByCommandArgs(c, NULL, ttl, replace);
        return;
    }

failed_syntax_error:
    addReply(c, shared.syntaxerr);
}

// RESTORE key ttl serialized-value [REPLACE] [ASYNC]
void restoreCommand(client* c) {
    int replace = 0, non_blocking = 0;
    for (int j = 4; j < c->argc; j++) {
        if (strcasecmp(c->argv[j]->ptr, "REPLACE") == 0) {
            replace = 1;
        } else if (strcasecmp(c->argv[j]->ptr, "ASYNC") == 0) {
            non_blocking = 1;
        } else {
            addReply(c, shared.syntaxerr);
            return;
        }
    }

    if (non_blocking) {
        if (c->flags & CLIENT_LUA) {
            addReplyError(c, "Option ASYNC is not allowed from scripts.");
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
    restoreAsyncCommandResetIfNeeded(c);

    restoreCommandArgs* args =
        initRestoreCommandArgs(c, c->argv[1], non_blocking);

    incrRefCount(c->argv[3]);
    listAddNodeTail(args->fragments, c->argv[3]);
    args->total_bytes += sdslen(c->argv[3]->ptr);

    if (!non_blocking) {
        restoreCommandByCommandArgs(c, args);
    } else {
        restoreAsyncCommandByCommandArgs(c, args, ttl, replace);
    }
}

// ---------------- BACKGROUND THREAD --------------------------------------- //

typedef struct {
    pthread_t thread;
    pthread_attr_t attr;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
    struct {
        list* jobs;
        list* done;
    } migrate, restore;
    int pipe_fds[2];
} migrateCommandThread;

static void* migrateCommandThreadMain(void* privdata) {
    migrateCommandThread* p = privdata;

    // TODO (jemalloc) fix arena id=0
    while (1) {
        migrateCommandArgs* migrate_args = NULL;
        restoreCommandArgs* restore_args = NULL;

        pthread_mutex_lock(&p->mutex);
        {
            while (listLength(p->migrate.jobs) == 0 &&
                   listLength(p->restore.jobs) == 0) {
                pthread_cond_wait(&p->cond, &p->mutex);
            }
            if (listLength(p->migrate.jobs) != 0) {
                migrate_args = listNodeValue(listFirst(p->migrate.jobs));
                listDelNode(p->migrate.jobs, listFirst(p->migrate.jobs));
            }
            if (listLength(p->restore.jobs) != 0) {
                restore_args = listNodeValue(listFirst(p->restore.jobs));
                listDelNode(p->restore.jobs, listFirst(p->restore.jobs));
            }
        }
        pthread_mutex_unlock(&p->mutex);

        if (migrate_args != NULL) {
            serverAssert(migrate_args->non_blocking &&
                         migrate_args->processing);
            if (migrateGenericCommandSendRequests(migrate_args)) {
                migrateGenericCommandFetchReplies(migrate_args);
            }
        }
        if (restore_args != NULL) {
            serverAssert(restore_args->non_blocking &&
                         restore_args->processing);
            restoreGenericCommandExtractPayload(restore_args);
        }

        pthread_mutex_lock(&p->mutex);
        {
            if (migrate_args != NULL) {
                listAddNodeTail(p->migrate.done, migrate_args);
            }
            if (restore_args != NULL) {
                listAddNodeTail(p->restore.done, restore_args);
            }
        }
        pthread_mutex_unlock(&p->mutex);

        serverAssert(write(p->pipe_fds[1], ".", 1) == 1);
    }
}

static void migrateCommandThreadReadEvent(aeEventLoop* el, int fd,
                                          void* privdata, int mask) {
    UNUSED(el);
    UNUSED(fd);
    UNUSED(mask);

    migrateCommandThread* p = privdata;

    char c;
    int n = read(p->pipe_fds[0], &c, sizeof(c));
    if (n != 1) {
        serverAssert(n == -1 && errno == EAGAIN);
    }

    while (1) {
        migrateCommandArgs* migrate_args = NULL;
        restoreCommandArgs* restore_args = NULL;

        pthread_mutex_lock(&p->mutex);
        {
            if (listLength(p->migrate.done) != 0) {
                migrate_args = listNodeValue(listFirst(p->migrate.done));
                listDelNode(p->migrate.done, listFirst(p->migrate.done));
            }
            if (listLength(p->restore.done) != 0) {
                restore_args = listNodeValue(listFirst(p->restore.done));
                listDelNode(p->restore.done, listFirst(p->restore.done));
            }
        }
        pthread_mutex_unlock(&p->mutex);

        if (migrate_args != NULL) {
            migrate_args->processing = 0;
            migrateAsyncCommandCallback(migrate_args);
        }
        if (restore_args != NULL) {
            restore_args->processing = 0;
            restoreAsyncCommandCallback(restore_args);
        }

        if (migrate_args == NULL && restore_args == NULL) {
            return;
        }
    }
}

static void migrateCommandThreadInit(migrateCommandThread* p) {
    size_t stacksize;
    pthread_attr_init(&p->attr);
    pthread_attr_getstacksize(&p->attr, &stacksize);
    while (stacksize < 4LL * 1024 * 1024) {
        stacksize = (stacksize < 1024) ? 1024 : stacksize * 2;
    }
    pthread_attr_setstacksize(&p->attr, stacksize);
    pthread_cond_init(&p->cond, NULL);
    pthread_mutex_init(&p->mutex, NULL);

    p->migrate.jobs = listCreate();
    p->migrate.done = listCreate();
    p->restore.jobs = listCreate();
    p->restore.done = listCreate();

    if (pipe(p->pipe_fds) != 0) {
        serverPanic("Fatal: create pipe '%s'.", strerror(errno));
        exit(1);
    }
    if (anetNonBlock(NULL, p->pipe_fds[0]) != ANET_OK) {
        serverPanic("Fatal: call anetNonBlock '%s'.", strerror(errno));
        exit(1);
    }
    if (aeCreateFileEvent(server.el, p->pipe_fds[0], AE_READABLE,
                          migrateCommandThreadReadEvent, p) == AE_ERR) {
        serverPanic("Fatal: call aeCreateFileEvent '%s'.", strerror(errno));
        exit(1);
    }

    int ret = pthread_create(&p->thread, &p->attr, migrateCommandThreadMain, p);
    if (ret != 0) {
        serverPanic("Fatal: call pthread_create '%s'.", strerror(ret));
        exit(1);
    }
}

static migrateCommandThread migrate_command_threads[1];

void migrateBackgroundThread(void) {
    migrateCommandThreadInit(&migrate_command_threads[0]);
}

static void migrateCommandThreadAddMigrateJobTail(migrateCommandArgs* args) {
    migrateCommandThread* p = &migrate_command_threads[0];
    migrateCommandArgs* migrate_args = args;

    serverAssert(!migrate_args->processing);
    migrate_args->processing = 1;

    pthread_mutex_lock(&p->mutex);
    {
        listAddNodeTail(p->migrate.jobs, migrate_args);
        pthread_cond_broadcast(&p->cond);
    }
    pthread_mutex_unlock(&p->mutex);
}

static void migrateCommandThreadAddRestoreJobTail(restoreCommandArgs* args) {
    migrateCommandThread* p = &migrate_command_threads[0];
    restoreCommandArgs* restore_args = args;

    serverAssert(!restore_args->processing);
    restore_args->processing = 1;

    pthread_mutex_lock(&p->mutex);
    {
        listAddNodeTail(p->restore.jobs, restore_args);
        pthread_cond_broadcast(&p->cond);
    }
    pthread_mutex_unlock(&p->mutex);
}

/* ---------------- TODO ---------------------------------------------------- */

void unblockClientFromRestore(client* c) { UNUSED(c); }
void freeRestoreCommandArgsFromFreeClient(client* c) { UNUSED(c); }
void restoreCloseTimedoutCommands(void) {}
