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
    robj *host, *port;

    int migrated;
    int num_keys;
    robj** keys_array;
    robj** vals_array;
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
    if (args->host != NULL) {
        decrRefCount(args->host);
    }
    if (args->port != NULL) {
        decrRefCount(args->port);
    }
    if (args->keys_array != NULL) {
        zfree(args->keys_array);
    }
    if (args->vals_array != NULL) {
        zfree(args->vals_array);
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

    args->host = c->argv[1];
    incrRefCount(args->host);

    args->port = c->argv[2];
    incrRefCount(args->port);

    /* Check if the keys are here. If at least one key is to migrate, do it
     * otherwise if all the keys are missing reply with "NOKEY" to signal
     * the caller there was nothing to migrate. We don't return an error in
     * this case, since often this is due to a normal condition like the key
     * expiring in the meantime. */

    args->keys = dictCreate(&objectKeyPointerValueDictType, NULL);
    for (int j = 0; j < num_keys; j++) {
        robj* key = c->argv[first_key + j];
        robj* val = lookupKeyRead(c->db, key);
        if (val != NULL && dictAdd(args->keys, key, val) != C_ERR) {
            incrRefCount(key);
            incrRefCount(val);
        }
    }
    args->num_keys = dictSize(args->keys);

    if (args->num_keys == 0) {
        addReplySds(c, sdsnew("+NOKEY\r\n"));
        return C_ERR;
    }

    /* Put all key/value pairs into a flatten array. */
    args->keys_array = zmalloc(sizeof(robj**) * args->num_keys);
    args->vals_array = zmalloc(sizeof(robj**) * args->num_keys);

    dictIterator* it = dictGetIterator(args->keys);
    dictEntry* entry;
    for (int i = 0; (entry = dictNext(it)) != NULL; i++) {
        args->keys_array[i] = dictGetKey(entry);
        args->vals_array[i] = dictGetVal(entry);
    }
    dictReleaseIterator(it);

    /* Rehash the keys dict if it's rehashing. */
    dictRehash(args->keys, 100);
    return C_OK;
}

static void migrateRewriteCommand(client* c, migrateCommandArgs* args) {
    /* Translate MIGRATE as DEL for replication/AOF. Note that we do
     * this only for the keys for which we received an acknowledgement
     * from the receiving Redis server. */
    if (!args->copy && args->migrated != 0) {
        robj** newargv = zmalloc(sizeof(robj*) * (1 + args->migrated));
        newargv[0] = createStringObject("DEL", 3);
        for (int i = 0; i < args->migrated; i++) {
            /* Populate the argument vector to replace the old one. */
            robj* key = args->keys_array[i];
            newargv[i + 1] = key;
            incrRefCount(key);

            /* No COPY option: remove the local key, signal the change. */
            dbDelete(c->db, key);
            signalModifiedKey(c->db, key);
            server.dirty++;
        }
        /* Note that the following call takes ownership of newargv. */
        replaceClientCommandVector(c, 1 + args->migrated, newargv);
    }
}

/* MIGRATE socket cache implementation.
 *
 * We take a map between host:ip and a TCP socket that we used to connect
 * to this instance in recent time.
 * This sockets are closed when the max number we cache is reached, and also
 * in serverCron() when they are around for more than a few seconds. */
#define MIGRATE_SOCKET_CACHE_ITEMS 64 /* max num of items in the cache. */
#define MIGRATE_SOCKET_CACHE_TTL 10   /* close cached sockets after 10 sec. */

typedef struct migrateCachedSocket {
    int fd;
    long last_dbid;
    time_t last_use_time;
} migrateCachedSocket;

/* Return a migrateCachedSocket containing a TCP socket connected with the
 * target instance, possibly returning a cached one.
 *
 * This function is responsible of sending errors to the client if a
 * connection can't be established. In this case -1 is returned.
 * Otherwise on success the socket is returned, and the caller should not
 * attempt to free it after usage.
 *
 * If the caller detects an error while using the socket, migrateCloseSocket()
 * should be called so that the connection will be created from scratch
 * the next time. */
migrateCachedSocket* migrateGetSocket(client* c, robj* host, robj* port,
                                      long timeout) {
    int fd;
    sds name = sdsempty();
    migrateCachedSocket* cs;

    /* Check if we have an already cached socket for this ip:port pair. */
    name = sdscatlen(name, host->ptr, sdslen(host->ptr));
    name = sdscatlen(name, ":", 1);
    name = sdscatlen(name, port->ptr, sdslen(port->ptr));
    cs = dictFetchValue(server.migrate_cached_sockets, name);
    if (cs) {
        sdsfree(name);
        cs->last_use_time = server.unixtime;
        return cs;
    }

    /* No cached socket, create one. */
    if (dictSize(server.migrate_cached_sockets) == MIGRATE_SOCKET_CACHE_ITEMS) {
        /* Too many items, drop one at random. */
        dictEntry* de = dictGetRandomKey(server.migrate_cached_sockets);
        cs = dictGetVal(de);
        close(cs->fd);
        zfree(cs);
        dictDelete(server.migrate_cached_sockets, dictGetKey(de));
    }

    /* Create the socket */
    fd = anetTcpNonBlockConnect(server.neterr, c->argv[1]->ptr,
                                atoi(c->argv[2]->ptr));
    if (fd == -1) {
        sdsfree(name);
        addReplyErrorFormat(c, "Can't connect to target node: %s",
                            server.neterr);
        return NULL;
    }
    anetEnableTcpNoDelay(server.neterr, fd);

    /* Check if it connects within the specified timeout. */
    if ((aeWait(fd, AE_WRITABLE, timeout) & AE_WRITABLE) == 0) {
        sdsfree(name);
        addReplySds(
            c, sdsnew("-IOERR error or timeout connecting to the client\r\n"));
        close(fd);
        return NULL;
    }

    /* Add to the cache and return it to the caller. */
    cs = zmalloc(sizeof(*cs));
    cs->fd = fd;
    cs->last_dbid = -1;
    cs->last_use_time = server.unixtime;
    dictAdd(server.migrate_cached_sockets, name, cs);
    return cs;
}

/* Free a migrate cached connection. */
void migrateCloseSocket(robj* host, robj* port) {
    sds name = sdsempty();
    migrateCachedSocket* cs;

    name = sdscatlen(name, host->ptr, sdslen(host->ptr));
    name = sdscatlen(name, ":", 1);
    name = sdscatlen(name, port->ptr, sdslen(port->ptr));
    cs = dictFetchValue(server.migrate_cached_sockets, name);
    if (!cs) {
        sdsfree(name);
        return;
    }

    close(cs->fd);
    zfree(cs);
    dictDelete(server.migrate_cached_sockets, name);
    sdsfree(name);
}

void migrateCloseTimedoutSockets(void) {
    dictIterator* di = dictGetSafeIterator(server.migrate_cached_sockets);
    dictEntry* de;

    while ((de = dictNext(di)) != NULL) {
        migrateCachedSocket* cs = dictGetVal(de);

        if ((server.unixtime - cs->last_use_time) > MIGRATE_SOCKET_CACHE_TTL) {
            close(cs->fd);
            zfree(cs);
            dictDelete(server.migrate_cached_sockets, dictGetKey(de));
        }
    }
    dictReleaseIterator(di);
}

/* MIGRATE host port key dbid timeout [COPY | REPLACE | AUTH password]
 *
 * On in the multiple keys form:
 *
 * MIGRATE host port "" dbid timeout [COPY | REPLACE | AUTH password] KEYS key1
 * key2 ... keyN */
void migrateCommand(client* c) {
    migrateCachedSocket* cs;
    int copy = 0, replace = 0, j;
    char* password = NULL;
    long timeout;
    long dbid;
    robj** ov = NULL;      /* Objects to migrate. */
    robj** kv = NULL;      /* Key names. */
    robj** newargv = NULL; /* Used to rewrite the command as DEL ... keys ... */
    rio cmd, payload;
    int may_retry = 1;
    int write_error = 0;
    int argv_rewritten = 0;

    /* To support the KEYS option we need the following additional state. */
    int first_key = 3; /* Argument index of the first key. */
    int num_keys = 1;  /* By default only migrate the 'key' argument. */

    /* Parse additional options */
    for (j = 6; j < c->argc; j++) {
        int moreargs = j < c->argc - 1;
        if (!strcasecmp(c->argv[j]->ptr, "copy")) {
            copy = 1;
        } else if (!strcasecmp(c->argv[j]->ptr, "replace")) {
            replace = 1;
        } else if (!strcasecmp(c->argv[j]->ptr, "auth")) {
            if (!moreargs) {
                addReply(c, shared.syntaxerr);
                return;
            }
            j++;
            password = c->argv[j]->ptr;
        } else if (!strcasecmp(c->argv[j]->ptr, "keys")) {
            if (sdslen(c->argv[3]->ptr) != 0) {
                addReplyError(c,
                              "When using MIGRATE KEYS option, the key argument"
                              " must be set to the empty string");
                return;
            }
            first_key = j + 1;
            num_keys = c->argc - j - 1;
            break; /* All the remaining args are keys. */
        } else {
            addReply(c, shared.syntaxerr);
            return;
        }
    }

    /* Sanity check */
    if (getLongFromObjectOrReply(c, c->argv[5], &timeout, NULL) != C_OK ||
        getLongFromObjectOrReply(c, c->argv[4], &dbid, NULL) != C_OK) {
        return;
    }
    if (timeout <= 0) timeout = 1000;

    /* Check if the keys are here. If at least one key is to migrate, do it
     * otherwise if all the keys are missing reply with "NOKEY" to signal
     * the caller there was nothing to migrate. We don't return an error in
     * this case, since often this is due to a normal condition like the key
     * expiring in the meantime. */
    ov = zrealloc(ov, sizeof(robj*) * num_keys);
    kv = zrealloc(kv, sizeof(robj*) * num_keys);
    int oi = 0;

    for (j = 0; j < num_keys; j++) {
        if ((ov[oi] = lookupKeyRead(c->db, c->argv[first_key + j])) != NULL) {
            kv[oi] = c->argv[first_key + j];
            oi++;
        }
    }
    num_keys = oi;
    if (num_keys == 0) {
        zfree(ov);
        zfree(kv);
        addReplySds(c, sdsnew("+NOKEY\r\n"));
        return;
    }

try_again:
    write_error = 0;

    /* Connect */
    cs = migrateGetSocket(c, c->argv[1], c->argv[2], timeout);
    if (cs == NULL) {
        zfree(ov);
        zfree(kv);
        return; /* error sent to the client by migrateGetSocket() */
    }

    rioInitWithBuffer(&cmd, sdsempty());

    /* Authentication */
    if (password) {
        serverAssertWithInfo(c, NULL, rioWriteBulkCount(&cmd, '*', 2));
        serverAssertWithInfo(c, NULL, rioWriteBulkString(&cmd, "AUTH", 4));
        serverAssertWithInfo(
            c, NULL, rioWriteBulkString(&cmd, password, sdslen(password)));
    }

    /* Send the SELECT command if the current DB is not already selected. */
    int select = cs->last_dbid != dbid; /* Should we emit SELECT? */
    if (select) {
        serverAssertWithInfo(c, NULL, rioWriteBulkCount(&cmd, '*', 2));
        serverAssertWithInfo(c, NULL, rioWriteBulkString(&cmd, "SELECT", 6));
        serverAssertWithInfo(c, NULL, rioWriteBulkLongLong(&cmd, dbid));
    }

    /* Create RESTORE payload and generate the protocol to call the command. */
    for (j = 0; j < num_keys; j++) {
        long long ttl = 0;
        long long expireat = getExpire(c->db, kv[j]);

        if (expireat != -1) {
            ttl = expireat - mstime();
            if (ttl < 1) ttl = 1;
        }
        serverAssertWithInfo(c, NULL,
                             rioWriteBulkCount(&cmd, '*', replace ? 5 : 4));

        if (server.cluster_enabled)
            serverAssertWithInfo(
                c, NULL, rioWriteBulkString(&cmd, "RESTORE-ASKING", 14));
        else
            serverAssertWithInfo(c, NULL,
                                 rioWriteBulkString(&cmd, "RESTORE", 7));
        serverAssertWithInfo(c, NULL, sdsEncodedObject(kv[j]));
        serverAssertWithInfo(
            c, NULL, rioWriteBulkString(&cmd, kv[j]->ptr, sdslen(kv[j]->ptr)));
        serverAssertWithInfo(c, NULL, rioWriteBulkLongLong(&cmd, ttl));

        /* Emit the payload argument, that is the serialized object using
         * the DUMP format. */
        createDumpPayload(&payload, ov[j]);
        serverAssertWithInfo(c, NULL,
                             rioWriteBulkString(&cmd, payload.io.buffer.ptr,
                                                sdslen(payload.io.buffer.ptr)));
        sdsfree(payload.io.buffer.ptr);

        /* Add the REPLACE option to the RESTORE command if it was specified
         * as a MIGRATE option. */
        if (replace)
            serverAssertWithInfo(c, NULL,
                                 rioWriteBulkString(&cmd, "REPLACE", 7));
    }

    /* Transfer the query to the other node in 64K chunks. */
    errno = 0;
    {
        sds buf = cmd.io.buffer.ptr;
        size_t pos = 0, towrite;
        int nwritten = 0;

        while ((towrite = sdslen(buf) - pos) > 0) {
            towrite = (towrite > (64 * 1024) ? (64 * 1024) : towrite);
            nwritten = syncWrite(cs->fd, buf + pos, towrite, timeout);
            if (nwritten != (signed)towrite) {
                write_error = 1;
                goto socket_err;
            }
            pos += nwritten;
        }
    }

    char buf0[1024]; /* Auth reply. */
    char buf1[1024]; /* Select reply. */
    char buf2[1024]; /* Restore reply. */

    /* Read the AUTH reply if needed. */
    if (password && syncReadLine(cs->fd, buf0, sizeof(buf0), timeout) <= 0)
        goto socket_err;

    /* Read the SELECT reply if needed. */
    if (select && syncReadLine(cs->fd, buf1, sizeof(buf1), timeout) <= 0)
        goto socket_err;

    /* Read the RESTORE replies. */
    int error_from_target = 0;
    int socket_error = 0;
    int del_idx = 1; /* Index of the key argument for the replicated DEL op. */

    if (!copy) newargv = zmalloc(sizeof(robj*) * (num_keys + 1));

    for (j = 0; j < num_keys; j++) {
        if (syncReadLine(cs->fd, buf2, sizeof(buf2), timeout) <= 0) {
            socket_error = 1;
            break;
        }
        if (buf0[0] == '-' || (select && buf1[0] == '-') || buf2[0] == '-') {
            /* On error assume that last_dbid is no longer valid. */
            if (!error_from_target) {
                cs->last_dbid = -1;
                char* errbuf;
                if (buf0[0] == '-')
                    errbuf = buf0;
                else if (select && buf1[0] == '-')
                    errbuf = buf1;
                else
                    errbuf = buf2;

                error_from_target = 1;
                addReplyErrorFormat(c, "Target instance replied with error: %s",
                                    errbuf + 1);
            }
        } else {
            if (!copy) {
                /* No COPY option: remove the local key, signal the change. */
                dbDelete(c->db, kv[j]);
                signalModifiedKey(c->db, kv[j]);
                server.dirty++;

                /* Populate the argument vector to replace the old one. */
                newargv[del_idx++] = kv[j];
                incrRefCount(kv[j]);
            }
        }
    }

    /* On socket error, if we want to retry, do it now before rewriting the
     * command vector. We only retry if we are sure nothing was processed
     * and we failed to read the first reply (j == 0 test). */
    if (!error_from_target && socket_error && j == 0 && may_retry &&
        errno != ETIMEDOUT) {
        goto socket_err; /* A retry is guaranteed because of tested
                            conditions.*/
    }

    /* On socket errors, close the migration socket now that we still have
     * the original host/port in the ARGV. Later the original command may be
     * rewritten to DEL and will be too later. */
    if (socket_error) migrateCloseSocket(c->argv[1], c->argv[2]);

    if (!copy) {
        /* Translate MIGRATE as DEL for replication/AOF. Note that we do
         * this only for the keys for which we received an acknowledgement
         * from the receiving Redis server, by using the del_idx index. */
        if (del_idx > 1) {
            newargv[0] = createStringObject("DEL", 3);
            /* Note that the following call takes ownership of newargv. */
            replaceClientCommandVector(c, del_idx, newargv);
            argv_rewritten = 1;
        } else {
            /* No key transfer acknowledged, no need to rewrite as DEL. */
            zfree(newargv);
        }
        newargv = NULL; /* Make it safe to call zfree() on it in the future. */
    }

    /* If we are here and a socket error happened, we don't want to retry.
     * Just signal the problem to the client, but only do it if we did not
     * already queue a different error reported by the destination server. */
    if (!error_from_target && socket_error) {
        may_retry = 0;
        goto socket_err;
    }

    if (!error_from_target) {
        /* Success! Update the last_dbid in migrateCachedSocket, so that we can
         * avoid SELECT the next time if the target DB is the same. Reply +OK.
         *
         * Note: If we reached this point, even if socket_error is true
         * still the SELECT command succeeded (otherwise the code jumps to
         * socket_err label. */
        cs->last_dbid = dbid;
        addReply(c, shared.ok);
    } else {
        /* On error we already sent it in the for loop above, and set
         * the currently selected socket to -1 to force SELECT the next time. */
    }

    sdsfree(cmd.io.buffer.ptr);
    zfree(ov);
    zfree(kv);
    zfree(newargv);
    return;

/* On socket errors we try to close the cached socket and try again.
 * It is very common for the cached socket to get closed, if just reopening
 * it works it's a shame to notify the error to the caller. */
socket_err:
    /* Cleanup we want to perform in both the retry and no retry case.
     * Note: Closing the migrate socket will also force SELECT next time. */
    sdsfree(cmd.io.buffer.ptr);

    /* If the command was rewritten as DEL and there was a socket error,
     * we already closed the socket earlier. While migrateCloseSocket()
     * is idempotent, the host/port arguments are now gone, so don't do it
     * again. */
    if (!argv_rewritten) migrateCloseSocket(c->argv[1], c->argv[2]);
    zfree(newargv);
    newargv = NULL; /* This will get reallocated on retry. */

    /* Retry only if it's not a timeout and we never attempted a retry
     * (or the code jumping here did not set may_retry to zero). */
    if (errno != ETIMEDOUT && may_retry) {
        may_retry = 0;
        goto try_again;
    }

    /* Cleanup we want to do if no retry is attempted. */
    zfree(ov);
    zfree(kv);
    addReplySds(
        c, sdscatprintf(sdsempty(),
                        "-IOERR error or timeout %s to target instance\r\n",
                        write_error ? "writing" : "reading"));
    return;
}
