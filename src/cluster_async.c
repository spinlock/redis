#include "server.h"

/* ============================ Iterators: singleObjectIterator ============================ */

#define STAGE_PREPARE 0
#define STAGE_PAYLOAD 1
#define STAGE_CHUNKED 2
#define STAGE_FILLTTL 3
#define STAGE_DONE    4

typedef struct {
    int stage;
    robj *key;
    robj *val;
    long long expire;
    unsigned long cursor;
    unsigned long lindex;
    unsigned long zindex;
} singleObjectIterator;

static singleObjectIterator *
createSingleObjectIterator(robj *key) {
    singleObjectIterator *it = zmalloc(sizeof(singleObjectIterator));
    it->stage = STAGE_PREPARE;
    it->key = key;
    incrRefCount(it->key);
    it->val = NULL;
    it->expire = 0;
    it->cursor = 0;
    it->lindex = 0;
    it->zindex = 0;
    return it;
}

static void
freeSingleObjectIterator(singleObjectIterator *it) {
    if (it->val != NULL) {
        decrRefCount(it->val);
    }
    decrRefCount(it->key);
    zfree(it);
}

static void
freeSingleObjectIteratorVoid(void *it) {
    freeSingleObjectIterator(it);
}

static int
singleObjectIteratorHasNext(singleObjectIterator *it) {
    return it->stage != STAGE_DONE;
}

static size_t
sdslenOrElse(robj *o, size_t len) {
    return sdsEncodedObject(o) ? sdslen(o->ptr) : len;
}

static void
singleObjectIteratorScanCallback(void *data, const dictEntry *de) {
    void **pd = (void **)data;
    list *l = pd[0];
    robj *o = pd[1];
    long long *n = pd[2];

    sds s[2] = {NULL, NULL};
    switch (o->type) {
    case OBJ_HASH:
        s[0] = dictGetKey(de);
        s[1] = dictGetVal(de);
        break;
    case OBJ_SET:
        s[0] = dictGetKey(de);
        break;
    }
    for (int i = 0; i < 2; i ++) {
        if (s[i] != NULL) {
            robj *obj = createStringObject((const char *)s[i], sdslen(s[i]));
            *n += sdslenOrElse(obj, 8);
            listAddNodeTail(l, obj);
        }
    }
}

static uint64_t
convertDoubleToRawBits(double value) {
    union {
        double d;
        uint64_t u;
    } fp;
    fp.d = value;
    return fp.u;
}

static double
convertRawBitsToDouble(uint64_t value) {
    union {
        double d;
        uint64_t u;
    } fp;
    fp.u = value;
    return fp.d;
}

static robj *
createRawStringObjectFromUint64(uint64_t v) {
    uint64_t p = intrev64ifbe(v);
    return createRawStringObject((char *)&p, sizeof(p));
}

static int
decodeUint64FromRawStringObject(robj *o, uint64_t *p) {
    if (sdsEncodedObject(o) && sdslen(o->ptr) == sizeof(uint64_t)) {
        *p = intrev64ifbe(*(uint64_t *)(o->ptr));
        return C_OK;
    }
    return C_ERR;
}

static long
estimateNumberOfRestoreCommandsObject(robj *val, long long maxbulks) {
    long long numbulks = 0;
    switch (val->type) {
    case OBJ_LIST:
        if (val->encoding == OBJ_ENCODING_QUICKLIST) {
            numbulks = listTypeLength(val);
        }
        break;
    case OBJ_HASH:
        if (val->encoding == OBJ_ENCODING_HT) {
            numbulks = hashTypeLength(val) * 2;
        }
        break;
    case OBJ_SET:
        if (val->encoding == OBJ_ENCODING_HT) {
            numbulks = setTypeSize(val);
        }
        break;
    case OBJ_ZSET:
        if (val->encoding == OBJ_ENCODING_SKIPLIST) {
            numbulks = zsetLength(val) * 2;
        }
        break;
    }

    /* 1x RESTORE-PAYLOAD */
    if (numbulks <= maxbulks) {
        return 1;
    }

    /* nx RESTORE-CHUNKED + 1x RESTORE-FILLTTL */
    return 1 + (numbulks + maxbulks - 1) / maxbulks;
}

static long
estimateNumberOfRestoreCommands(redisDb *db, robj *key, long long maxbulks) {
    robj *val = lookupKeyWrite(db, key);
    if (val == NULL) {
        return 0;
    }
    return 1 + estimateNumberOfRestoreCommandsObject(val, maxbulks);
}

static asyncMigrationClient *getAsyncMigrationClient(int db);

static int
singleObjectIteratorNextStagePrepare(client *c, singleObjectIterator *it, unsigned int maxbulks) {
    serverAssert(it->stage == STAGE_PREPARE);
    robj *key = it->key;
    robj *val = lookupKeyWrite(c->db, key);
    if (val == NULL) {
        it->stage = STAGE_DONE;
        return 0;
    }
    it->val = val;
    incrRefCount(it->val);
    it->expire = getExpire(c->db, key);

    int sending_msgs = 0;

    asyncMigrationClient *ac = getAsyncMigrationClient(c->db->id);
    if (ac->c == c) {
        if (ac->init == 0) {
            ac->init = 1;
            if (server.requirepass != NULL) {
                /* RESTORE-ASYNC-AUTH $passwd */
                addReplyMultiBulkLen(c, 2);
                addReplyBulkCString(c, "RESTORE-ASYNC-AUTH");
                addReplyBulkCString(c, server.requirepass);
                sending_msgs ++;
            }
            do {
                /* RESTORE-ASYNC select $db */
                addReplyMultiBulkLen(c, 3);
                addReplyBulkCString(c, "RESTORE-ASYNC");
                addReplyBulkCString(c, "select");
                addReplyBulkLongLong(c, c->db->id);
                sending_msgs ++;
            } while (0);
        }
    }

    do {
        /* RESTORE-ASYNC delete $key */
        addReplyMultiBulkLen(c, 3);
        addReplyBulkCString(c, "RESTORE-ASYNC");
        addReplyBulkCString(c, "delete");
        addReplyBulk(c, key);
        sending_msgs ++;
    } while(0);

    long n = estimateNumberOfRestoreCommandsObject(val, maxbulks);
    if (n != 1) {
        it->stage = STAGE_CHUNKED;
    } else {
        it->stage = STAGE_PAYLOAD;
    }
    return sending_msgs;
}

extern void createDumpPayload(rio *payload, robj *o);

static int
singleObjectIteratorNextStagePayload(client *c, singleObjectIterator *it) {
    serverAssert(it->stage == STAGE_PAYLOAD);
    robj *key = it->key;
    robj *val = it->val;
    long long ttlms = 0;
    if (it->expire != -1) {
        ttlms = it->expire - mstime();
        if (ttlms < 1) {
            ttlms = 1;
        }
    }

    if (val->type != OBJ_STRING) {
        rio payload;
        createDumpPayload(&payload, val);
        do {
            /* RESTORE-ASYNC object $key $ttlms $payload */
            addReplyMultiBulkLen(c, 5);
            addReplyBulkCString(c, "RESTORE-ASYNC");
            addReplyBulkCString(c, "object");
            addReplyBulk(c, key);
            addReplyBulkLongLong(c, ttlms);
            addReplyBulkSds(c, payload.io.buffer.ptr);
        } while (0);
    } else {
        do {
            /* RESTORE-ASYNC string $key $ttlms $payload */
            addReplyMultiBulkLen(c, 5);
            addReplyBulkCString(c, "RESTORE-ASYNC");
            addReplyBulkCString(c, "string");
            addReplyBulk(c, key);
            addReplyBulkLongLong(c, ttlms);
            addReplyBulk(c, val);
        } while (0);
    }

    it->stage = STAGE_DONE;
    return 1;
}

static int
singleObjectIteratorNextStageFillTTL(client *c, singleObjectIterator *it) {
    serverAssert(it->stage == STAGE_FILLTTL);
    robj *key = it->key;
    long long ttlms = 0;
    if (it->expire != -1) {
        ttlms = it->expire - mstime();
        if (ttlms < 1) {
            ttlms = 1;
        }
    }

    do {
        /* RESTORE-ASYNC expire $key $ttlms */
        addReplyMultiBulkLen(c, 4);
        addReplyBulkCString(c, "RESTORE-ASYNC");
        addReplyBulkCString(c, "expire");
        addReplyBulk(c, key);
        addReplyBulkLongLong(c, ttlms);
    } while (0);

    it->stage = STAGE_DONE;
    return 1;
}

extern zskiplistNode* zslGetElementByRank(zskiplist *zsl, unsigned long rank);

static int
singleObjectIteratorNextStageChunkedTypeList(singleObjectIterator *it,
        list *ll, robj *val, long long *psize, unsigned int maxbulks, unsigned int maxbytes) {
    serverAssert(val->type == OBJ_LIST);
    serverAssert(val->encoding == OBJ_ENCODING_QUICKLIST);

    long long done = 0, len = 0;

    listTypeIterator *li = listTypeInitIterator(val, it->lindex, LIST_TAIL);

    do {
        listTypeEntry entry;
        if (listTypeNext(li, &entry)) {
            quicklistEntry *qe = &(entry.entry);
            robj *ele;
            if (qe->value) {
                ele = createStringObject((const char *)qe->value, qe->sz);
            } else {
                ele = createStringObjectFromLongLong(qe->longval);
            }
            len += sdslenOrElse(ele, 8);
            listAddNodeTail(ll, ele);

            it->lindex ++;
        } else {
            done = 1;
        }
    } while (!done
            && listLength(ll) < maxbulks && len < maxbytes);

    listTypeReleaseIterator(li);

    *psize = listTypeLength(val);
    return done != 0;
}

static int
singleObjectIteratorNextStageChunkedTypeZSet(singleObjectIterator *it,
        list *ll, robj *val, long long *psize, unsigned int maxbulks, unsigned int maxbytes) {
    serverAssert(val->type == OBJ_ZSET);
    serverAssert(val->encoding == OBJ_ENCODING_SKIPLIST);

    long long done = 0, len = 0;

    long long rank = (long long)zsetLength(val) - it->zindex;
    zset *zs = val->ptr;
    zskiplistNode *node = (rank >= 1) ? zslGetElementByRank(zs->zsl, rank) : NULL;

    do {
        if (node != NULL) {
            robj *field = createStringObject((const char *)node->ele, sdslen(node->ele));
            len += sdslenOrElse(field, 8);
            listAddNodeTail(ll, field);

            uint64_t u8 = convertDoubleToRawBits(node->score);
            robj *score = createRawStringObjectFromUint64(u8);
            len += sdslenOrElse(score, 8);
            listAddNodeTail(ll, score);

            node = node->backward;
            it->zindex ++;
        } else {
            done = 1;
        }
    } while (!done
            && listLength(ll) < maxbulks && len < maxbytes);

    *psize = zsetLength(val);
    return done != 0;
}

static int
singleObjectIteratorNextStageChunkedTypeHashOrDict(singleObjectIterator *it,
        list *ll, robj *val, long long *psize, unsigned int maxbulks, unsigned int maxbytes) {
    serverAssert(val->type == OBJ_HASH || val->type == OBJ_SET);
    serverAssert(val->encoding == OBJ_ENCODING_HT);

    long long done = 0, len = 0;

    int loop = maxbulks * 10;
    if (loop < 100) {
        loop = 100;
    }
    dict *ht = val->ptr;
    void *pd[] = {ll, val, &len};

    do {
        it->cursor = dictScan(ht, it->cursor, singleObjectIteratorScanCallback, NULL, pd);
        if (it->cursor == 0) {
            done = 1;
        }
    } while (!done && (-- loop) >= 0
            && listLength(ll) < maxbulks && len < maxbytes);

    *psize = dictSize(ht);
    return done != 0;
}

static int
singleObjectIteratorNextStageChunked(client *c, singleObjectIterator *it,
        long long timeout, unsigned int maxbulks, unsigned int maxbytes) {
    serverAssert(it->stage == STAGE_CHUNKED);
    robj *key = it->key;
    robj *val = it->val;
    long long ttlms = timeout * 3;
    if (ttlms < 1000) {
        ttlms = 1000;
    }

    const char *type = NULL;
    switch (val->type) {
    case OBJ_LIST:
        type = "list"; break;
    case OBJ_HASH:
        type = "hash"; break;
    case OBJ_SET:
        type = "dict"; break;
    case OBJ_ZSET:
        type = "zset"; break;
    default:
        serverPanic("invalid object.type=%d of singleObjectIterator", val->type);
    }

    list *ll = listCreate();
    listSetFreeMethod(ll, decrRefCountVoid);

    long long done = 0, maxsize = 0;

    switch (val->type) {
    case OBJ_LIST:
        done = singleObjectIteratorNextStageChunkedTypeList(it, ll, val,
                &maxsize, maxbulks, maxbytes);
        break;
    case OBJ_ZSET:
        done = singleObjectIteratorNextStageChunkedTypeZSet(it, ll, val,
                &maxsize, maxbulks, maxbytes);
        break;
    case OBJ_HASH: case OBJ_SET:
        done = singleObjectIteratorNextStageChunkedTypeHashOrDict(it, ll, val,
                &maxsize, maxbulks, maxbytes);
        break;
    }

    int sending_msgs = 0;

    if (listLength(ll) != 0) {
        /* RESTORE-ASYNC list/hash/zset/dict $key $ttlms $maxsize [$arg1 ...] */
        addReplyMultiBulkLen(c, 5 + listLength(ll));
        addReplyBulkCString(c, "RESTORE-ASYNC");
        addReplyBulkCString(c, type);
        addReplyBulk(c, key);
        addReplyBulkLongLong(c, ttlms);
        addReplyBulkLongLong(c, maxsize);

        while (listLength(ll) != 0) {
            listNode *head = listFirst(ll);
            robj *bulk = listNodeValue(head);
            addReplyBulk(c, bulk);
            listDelNode(ll, head);
        }
        sending_msgs ++;
    }
    listRelease(ll);

    if (done) {
        it->stage = STAGE_FILLTTL;
    }
    return sending_msgs;
}

static int
singleObjectIteratorNext(client *c, singleObjectIterator *it,
        long long timeout, unsigned int maxbulks, unsigned int maxbytes) {
    /* *
     * STAGE_PREPARE ---> STAGE_PAYLOAD ---> STAGE_DONE
     *     |                                      A
     *     V                                      |
     *     +------------> STAGE_CHUNKED ---> STAGE_FILLTTL
     *                      A       |
     *                      |       V
     *                      +-------+
     * */
    switch (it->stage) {
    case STAGE_PREPARE:
        return singleObjectIteratorNextStagePrepare(c, it, maxbulks);
    case STAGE_PAYLOAD:
        return singleObjectIteratorNextStagePayload(c, it);
    case STAGE_CHUNKED:
        return singleObjectIteratorNextStageChunked(c, it, timeout, maxbulks, maxbytes);
    case STAGE_FILLTTL:
        return singleObjectIteratorNextStageFillTTL(c, it);
    case STAGE_DONE:
        return 0;
    default:
        serverPanic("invalid stage=%d of singleObjectIterator", it->stage);
    }
}

/* ============================ Iterators: batchedObjectIterator =========================== */

typedef struct {
    long long timeout;
    long long maxbulks;
    long long maxbytes;
    dict *keys;
    list *iterator_list;
    list *released_keys;
    long estimate_msgs;
} batchedObjectIterator;

static batchedObjectIterator *
createBatchedObjectIterator(long long timeout, unsigned int maxbulks, unsigned int maxbytes) {
    batchedObjectIterator *it = zmalloc(sizeof(batchedObjectIterator));
    it->timeout = timeout;
    it->maxbulks = maxbulks;
    it->maxbytes = maxbytes;
    it->keys = dictCreate(&setDictType, NULL);
    it->iterator_list = listCreate();
    listSetFreeMethod(it->iterator_list, freeSingleObjectIteratorVoid);
    it->released_keys = listCreate();
    listSetFreeMethod(it->released_keys, decrRefCountVoid);
    it->estimate_msgs = 0;
    return it;
}

static void
freeBatchedObjectIterator(batchedObjectIterator *it) {
    dictRelease(it->keys);
    listRelease(it->iterator_list);
    listRelease(it->released_keys);
    zfree(it);
}

static int
batchedObjectIteratorHasNext(batchedObjectIterator *it) {
    list *ll = it->iterator_list;
    while (listLength(ll) != 0) {
        listNode *head = listFirst(ll);
        singleObjectIterator *sp = listNodeValue(head);
        if (singleObjectIteratorHasNext(sp)) {
            return 1;
        }
        if (sp->val != NULL) {
            incrRefCount(sp->key);
            listAddNodeTail(it->released_keys, sp->key);
        }
        listDelNode(ll, head);
    }
    return 0;
}

static int
batchedObjectIteratorNext(client *c, batchedObjectIterator *it) {
    list *ll = it->iterator_list;
    if (listLength(ll) != 0) {
        listNode *head = listFirst(ll);
        singleObjectIterator *sp = listNodeValue(head);
        return singleObjectIteratorNext(c, sp, it->timeout, it->maxbulks, it->maxbytes);
    }
    return 0;
}

static int
batchedObjectIteratorContains(batchedObjectIterator *it, robj *key) {
    return dictFind(it->keys, key->ptr) != NULL;
}

static int
batchedObjectIteratorAddKey(redisDb *db, batchedObjectIterator *it, robj *key) {
    if (batchedObjectIteratorContains(it, key)) {
        return 0;
    }
    dictAdd(it->keys, sdsdup(key->ptr), NULL);

    listAddNodeTail(it->iterator_list, createSingleObjectIterator(key));
    it->estimate_msgs += estimateNumberOfRestoreCommands(db, key, it->maxbulks);
    return 1;
}

/* ============================ Clients for Asynchronous Migration ========================= */

static asyncMigrationClient*
getAsyncMigrationClient(int db) {
    return &server.async_migration_clients[db];
}

static void
asyncMigrationClientInterrupt(asyncMigrationClient *ac, const char *errmsg) {
    batchedObjectIterator *it = ac->batched_iterator;
    list *ll = ac->blocked_clients;
    while (listLength(ll) != 0) {
        listNode *head = listFirst(ll);
        client *c = listNodeValue(head);
        serverAssert(c->migration_waitq == ll);

        if (errmsg != NULL) {
            addReplyError(c, errmsg);
        } else {
            addReplyLongLong(c, (it != NULL) ? listLength(it->released_keys) : -1);
        }

        c->migration_waitq = NULL;
        listDelNode(ll, head);

        unblockClient(c);
    }
}

void
unblockClientFromAsyncMigration(client *c) {
    list *ll = c->migration_waitq;
    if (ll != NULL) {
        listNode *node = listSearchKey(ll, c);
        serverAssert(node != NULL);

        c->migration_waitq = NULL;
        listDelNode(ll, node);
    }
}

void
releaseClientFromAsyncMigration(client *c) {
    asyncMigrationClient *ac = getAsyncMigrationClient(c->db->id);
    serverAssert(ac->c == c);

    batchedObjectIterator *it = ac->batched_iterator;

    serverLog(LL_WARNING, "async_migration: lost connection %s:%d (DB=%d): "
            "sending_msgs = %ld, delivered_msgs = %lld, "
            "blocked_clients = %ld, batched_iterator = %ld"
            "timeout = %lld(ms), elapsed = %lld(ms)",
            ac->host, ac->port, c->db->id, ac->sending_msgs, ac->delivered_msgs,
            (long)listLength(ac->blocked_clients), (it != NULL) ? (long)listLength(it->iterator_list) : -1,
            ac->timeout, mstime() - ac->lastuse);

    asyncMigrationClientInterrupt(ac, "interrupted: lost connection");

    sdsfree(ac->host);
    if (it != NULL) {
        freeBatchedObjectIterator(it);
    }
    listRelease(ac->blocked_clients);

    c->flags &= ~CLIENT_ASYNC_MIGRATION;

    memset(ac, 0, sizeof(*ac));
}

static int
asyncMigartionClientCancelErrorFormat(int db, const char *fmt, ...) {
    asyncMigrationClient *ac = getAsyncMigrationClient(db);
    if (ac->c == NULL) {
        return 0;
    }
    va_list ap;
    va_start(ap, fmt);
    sds errmsg = sdscatvprintf(sdsempty(), fmt, ap);
    va_end(ap);

    serverLog(LL_WARNING, "async_migration: canceled connection %s:%d (DB=%d) (%s)",
            ac->host, ac->port, db, errmsg);

    asyncMigrationClientInterrupt(ac, errmsg);
    freeClient(ac->c);

    sdsfree(errmsg);

    serverAssert(ac->c == NULL && ac->batched_iterator == NULL);
    return 1;
}

static asyncMigrationClient *
asyncMigrationClientOpen(int db, sds host, int port, int reuse, long long timeout) {
    asyncMigrationClient *ac = getAsyncMigrationClient(db);
    if (ac->c != NULL && reuse) {
        if (ac->port == port && !strcmp(ac->host, host)) {
            return ac;
        }
    }

    int fd = anetTcpNonBlockConnect(server.neterr, host, port);
    if (fd == -1) {
        serverLog(LL_WARNING, "async_migration: anetTcpNonBlockConnect %s:%d (DB=%d) failed (%s)",
            host, port, db, server.neterr);
        return NULL;
    }

    anetEnableTcpNoDelay(NULL, fd);

    int wait = timeout;
    if (wait > 10) {
        wait = 10;
    }
    if ((aeWait(fd, AE_WRITABLE, wait) & AE_WRITABLE) == 0) {
        serverLog(LL_WARNING, "async_migration: aeWait %s:%d (DB=%d) failed (io error or timeout)",
                host, port, db);
        close(fd);
        return NULL;
    }

    client *c = createClient(fd);
    if (c == NULL) {
        serverLog(LL_WARNING, "async_migration: createClient %s:%d (DB=%d) failed (%s)",
                host, port, db, server.neterr);
        return NULL;
    }
    if (selectDb(c, db) != C_OK) {
        serverLog(LL_WARNING, "async_migration: selectDb %s:%d (DB=%d) failed",
                host, port, db);
        freeClient(c);
        return NULL;
    }
    asyncMigartionClientCancelErrorFormat(db, "interrupted: replaced by %s:%d (reuse=%d)",
            host, port, reuse);

    c->flags |= CLIENT_ASYNC_MIGRATION;
    c->authenticated = 1;

    ac->c = c;
    ac->init = 0;
    ac->host = sdsdup(host);
    ac->port = port;
    ac->timeout = timeout;
    ac->lastuse = mstime();
    ac->sending_msgs = 0;
    ac->delivered_msgs = 0;
    ac->blocked_clients = listCreate();
    ac->batched_iterator = NULL;

    serverLog(LL_WARNING, "async_migration: connect to %s:%d (DB=%d) OK",
            host, port, db);
    return ac;
}

static int
asyncMigrationClientStatusOrBlock(client *c, int block) {
    asyncMigrationClient *ac = getAsyncMigrationClient(c->db->id);
    if (ac->c == NULL) {
        return 0;
    }
    batchedObjectIterator *it = ac->batched_iterator;
    if (it == NULL) {
        return 0;
    }
    if (!block) {
        return 1;
    }
    serverAssert(c->migration_waitq == NULL);

    list *ll = ac->blocked_clients;

    c->migration_waitq = ll;
    listAddNodeTail(ll, c);

    blockClient(c, BLOCKED_ASYNC_MIGRATION);
    return 1;
}

void
cleanupClientsForAsyncMigration() {
    for (int db = 0; db < server.dbnum; db ++) {
        asyncMigrationClient *ac = getAsyncMigrationClient(db);
        if (ac->c == NULL) {
            continue;
        }
        batchedObjectIterator *it = ac->batched_iterator;
        long long timeout = (it != NULL) ? ac->timeout : 1000 * 60;
        if (mstime() - ac->lastuse <= timeout) {
            continue;
        }
        asyncMigartionClientCancelErrorFormat(db, (it != NULL) ?
                "interrupted: migration timeout" : "interrupted: idle timeout");
    }
}

/* ============================ Command: MIGRATE-ASNYC-DUMP ================================ */

/* *
 * MIGRATE-ASYNC-DUMP $timeout $maxbulks $key1 [$key2 ...]
 * */
void
migrateAsyncDumpCommand(client *c) {
    long long timeout;
    if (getLongLongFromObject(c->argv[1], &timeout) != C_OK ||
            !(timeout >= 0 && timeout <= INT_MAX)) {
        addReplyErrorFormat(c, "invalid value of timeout (%s)",
                c->argv[1]->ptr);
        return;
    }
    if (timeout == 0) {
        timeout = 1000 * 10;
    }

    long long maxbulks;
    if (getLongLongFromObject(c->argv[2], &maxbulks) != C_OK ||
            !(maxbulks >= 0 && maxbulks <= INT_MAX / 2)) {
        addReplyErrorFormat(c, "invalid value of maxbulks (%s)",
                c->argv[2]->ptr);
        return;
    }
    if (maxbulks == 0) {
        maxbulks = 200;
    }

    long long maxbytes = INT_MAX / 2;

    batchedObjectIterator *it = createBatchedObjectIterator(timeout, maxbulks, maxbytes);
    for (int i = 3; i < c->argc; i ++) {
        batchedObjectIteratorAddKey(c->db, it, c->argv[i]);
    }

    void *ptr = addDeferredMultiBulkLength(c);
    int total = 0;
    while (batchedObjectIteratorHasNext(it)) {
        total += batchedObjectIteratorNext(c, it);
    }
    setDeferredMultiBulkLength(c, ptr, total);

    freeBatchedObjectIterator(it);
}

/* ============================ Command: MIGRATE-ASNYC ===================================== */

static unsigned int
asyncMigrationClientBufferLimit(unsigned int maxbytes) {
    clientBufferLimitsConfig *p = &server.client_obuf_limits[CLIENT_TYPE_NORMAL];
    if (p->soft_limit_bytes != 0 && p->soft_limit_bytes < maxbytes) {
        maxbytes = p->soft_limit_bytes;
    }
    if (p->hard_limit_bytes != 0 && p->hard_limit_bytes < maxbytes) {
        maxbytes = p->hard_limit_bytes;
    }
    return maxbytes;
}

static int
asyncMigrationNextInMicroseconds(asyncMigrationClient *ac, int atleast, long long usecs) {
    batchedObjectIterator *it = ac->batched_iterator;
    long long deadline = ustime() + usecs;
    int sending_msgs = 0;
    while (batchedObjectIteratorHasNext(it)) {
        if ((unsigned long)it->maxbytes <= getClientOutputBufferMemoryUsage(ac->c)) {
            break;
        }
        if ((sending_msgs += batchedObjectIteratorNext(ac->c, it)) >= atleast && deadline <= ustime()) {
            break;
        }
    }
    return sending_msgs;
}

/* *
 * MIGRATE-ASYNC $host $port $timeout $maxbulks $maxbytes $key1 [$key2 ...]
 * */
void
migrateAsyncCommand(client *c) {
    if (asyncMigrationClientStatusOrBlock(c, 0)) {
        addReplyError(c, "the specified DB is being migrated");
        return;
    }

    sds host = c->argv[1]->ptr;

    long long port;
    if (getLongLongFromObject(c->argv[2], &port) != C_OK ||
            !(port >= 1 && port < 65536)) {
        addReplyErrorFormat(c, "invalid value of port (%s)",
                c->argv[2]->ptr);
        return;
    }

    long long timeout;
    if (getLongLongFromObject(c->argv[3], &timeout) != C_OK ||
            !(timeout >= 0 && timeout <= INT_MAX)) {
        addReplyErrorFormat(c, "invalid value of timeout (%s)",
                c->argv[3]->ptr);
        return;
    }
    if (timeout == 0) {
        timeout = 1000 * 10;
    }

    long long maxbulks;
    if (getLongLongFromObject(c->argv[4], &maxbulks) != C_OK ||
            !(maxbulks >= 0 && maxbulks <= INT_MAX / 2)) {
        addReplyErrorFormat(c, "invalid value of maxbulks (%s)",
                c->argv[4]->ptr);
        return;
    }
    if (maxbulks == 0) {
        maxbulks = 200;
    }
    if (maxbulks > 2000) {
        maxbulks = 2000;
    }

    long long maxbytes;
    if (getLongLongFromObject(c->argv[5], &maxbytes) != C_OK ||
            !(maxbytes >= 0 && maxbytes <= INT_MAX / 2)) {
        addReplyErrorFormat(c, "invalid value of maxbytes (%s)",
                c->argv[5]->ptr);
        return;
    }
    if (maxbytes == 0) {
        maxbytes = 1024 * 1024;
    }
    maxbytes = asyncMigrationClientBufferLimit(maxbytes);

    asyncMigrationClient *ac = asyncMigrationClientOpen(c->db->id, host, port, 1, timeout);
    if (ac == NULL) {
        addReplyErrorFormat(c, "connect to %s:%d failed", host, (int)port);
        return;
    }
    serverAssert(ac->sending_msgs == 0);
    serverAssert(listLength(ac->blocked_clients) == 0 && ac->batched_iterator == NULL);

    batchedObjectIterator *it = createBatchedObjectIterator(timeout, maxbulks, maxbytes);
    for (int i = 6; i < c->argc; i ++) {
        batchedObjectIteratorAddKey(c->db, it, c->argv[i]);
    }

    ac->timeout = timeout;
    ac->lastuse = mstime();
    ac->sending_msgs += asyncMigrationNextInMicroseconds(ac, 4, 500);
    ac->batched_iterator = it;

    asyncMigrationClientStatusOrBlock(c, 1);

    if (ac->sending_msgs != 0) {
        return;
    }
    asyncMigrationClientInterrupt(ac, NULL);

    ac->batched_iterator = NULL;
    freeBatchedObjectIterator(it);
}

/* ============================ Command: MIGRATE-ASNYC-{FENCE/CANCEL/STATUS} =============== */

/* *
 * MIGRATE-ASYNC-FENCE
 * */
void
migrateAsyncFenceCommand(client *c) {
    if (asyncMigrationClientStatusOrBlock(c, 1)) {
        return;
    }
    addReplyLongLong(c, -1);
}

/* *
 * MIGRATE-ASYNC-CANCEL
 * */
void
migrateAsyncCancelCommand(client *c) {
    addReplyLongLong(c, asyncMigartionClientCancelErrorFormat(c->db->id, "interrupted: canceled"));
}

/* ============================ Command: RESTORE-ASYNC-AUTH ================================ */

static void
asyncMigrationReplyAckString(client *c, const char *msg) {
    do {
        /* RESTORE-ASYNC-ACK $errno $message */
        addReplyMultiBulkLen(c, 3);
        addReplyBulkCString(c, "RESTORE-ASYNC-ACK");
        addReplyBulkLongLong(c, 0);
        addReplyBulkCString(c, msg);
    } while (0);
}

static void
asyncMigrationReplyAckErrorFormat(client *c, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    sds errmsg = sdscatvprintf(sdsempty(), fmt, ap);
    va_end(ap);

    do {
        /* RESTORE-ASYNC-ACK $errno $message */
        addReplyMultiBulkLen(c, 3);
        addReplyBulkCString(c, "RESTORE-ASYNC-ACK");
        addReplyBulkLongLong(c, 1);
        addReplyBulkSds(c, errmsg);
    } while (0);

    c->flags |= CLIENT_CLOSE_AFTER_REPLY;
}

extern int time_independent_strcmp(const char *a, const char *b);

/* *
 * RESTORE-ASYNC-AUTH $passwd
 * */
void
restoreAsyncAuthCommand(client *c) {
    if (!server.requirepass) {
        asyncMigrationReplyAckErrorFormat(c, "Client sent AUTH, but no password is set");
        return;
    }
    if (!time_independent_strcmp(c->argv[1]->ptr, server.requirepass)) {
        c->authenticated = 1;
        asyncMigrationReplyAckString(c, "OK");
    } else {
        c->authenticated = 0;
        asyncMigrationReplyAckErrorFormat(c, "invalid password");
    }
}

/* ============================ Command: RESTORE-ASYNC ===================================== */

/* RESTORE-ASYNC select $db */
static int
restoreAsyncHandleOrReplySelectDb(client *c) {
    long long db;
    if (getLongLongFromObject(c->argv[2], &db) != C_OK ||
            !(db >= 0 && db <= INT_MAX) || selectDb(c, db) != C_OK) {
        asyncMigrationReplyAckErrorFormat(c, "invalid value of db (%s)",
                c->argv[2]->ptr);
        return C_ERR;
    }
    return C_OK;
}

/* RESTORE-ASYNC delete $key */
static int
restoreAsyncHandleOrReplyDeleteKey(client *c, robj *key) {
    if (dbDelete(c->db, key)) {
        signalModifiedKey(c->db, key);
        server.dirty ++;
    }
    return C_OK;
}

/* RESTORE-ASYNC expire $key $ttlms */
static int
restoreAsyncHandleOrReplyExpireKey(client *c, robj *key) {
    robj *val = lookupKeyWrite(c->db, key);
    if (val == NULL) {
        asyncMigrationReplyAckErrorFormat(c, "the specified key doesn't exist (%s)",
                key->ptr);
        return C_ERR;
    }
    return C_OK;
}

extern int verifyDumpPayload(unsigned char *p, size_t len);

/* RESTORE-ASYNC object $key $ttlms $payload */
static int
restoreAsyncHandleOrReplyTypeObject(client *c, robj *key) {
    if (lookupKeyWrite(c->db, key) != NULL) {
        asyncMigrationReplyAckErrorFormat(c, "the specified key already exists (%s)",
                key->ptr);
        return C_ERR;
    }

    rio payload;
    void *bytes = c->argv[4]->ptr;
    if (verifyDumpPayload(bytes, sdslen(bytes)) != C_OK) {
        asyncMigrationReplyAckErrorFormat(c, "invalid payload checksum (%s)",
                key->ptr);
        return C_ERR;
    }
    rioInitWithBuffer(&payload, bytes);

    int type = rdbLoadObjectType(&payload);
    if (type == -1) {
        asyncMigrationReplyAckErrorFormat(c, "invalid payload type (%s)",
                key->ptr);
        return C_ERR;
    }

    robj *val = rdbLoadObject(type, &payload);
    if (val == NULL) {
        asyncMigrationReplyAckErrorFormat(c, "invalid payload body (%s)",
                key->ptr);
        return C_ERR;
    }

    dbAdd(c->db, key, val);
    return C_OK;
}

/* RESTORE-ASYNC string $key $ttlms $payload */
static int
restoreAsyncHandleOrReplyTypeString(client *c, robj *key) {
    if (lookupKeyWrite(c->db, key) != NULL) {
        asyncMigrationReplyAckErrorFormat(c, "the specified key already exists (%s)",
                key->ptr);
        return C_ERR;
    }

    robj *val = c->argv[4] = tryObjectEncoding(c->argv[4]);

    incrRefCount(val);
    dbAdd(c->db, key, val);
    return C_OK;
}

/* RESTORE-ASYNC list $key $ttlms $maxsize [$elem1 ...] */
static int
restoreAsyncHandleOrReplyTypeList(client *c, robj *key) {
    robj *val = lookupKeyWrite(c->db, key);
    if (val != NULL) {
        if (val->type != OBJ_LIST || val->encoding != OBJ_ENCODING_QUICKLIST) {
            asyncMigrationReplyAckErrorFormat(c, "wrong type (expect=%d/%d,got=%d/%d)",
                    OBJ_LIST, OBJ_ENCODING_QUICKLIST, val->type, val->encoding);
            return C_ERR;
        }
    } else {
        val = createQuicklistObject();
        quicklistSetOptions(val->ptr, server.list_max_ziplist_size,
                server.list_compress_depth);
        dbAdd(c->db, key, val);
    }

    robj **argv = &c->argv[5]; int argc = c->argc - 5;

    for (int i = 0; i < argc; i ++) {
        listTypePush(val, argv[i], LIST_TAIL);
    }
    return C_OK;
}

/* RESTORE-ASYNC hash $key $ttlms $maxsize [$hkey1 $hval1 ...] */
static int
restoreAsyncHandleOrReplyTypeHash(client *c, robj *key, long long size) {
    robj *val = lookupKeyWrite(c->db, key);
    if (val != NULL) {
        if (val->type != OBJ_HASH || val->encoding != OBJ_ENCODING_HT) {
            asyncMigrationReplyAckErrorFormat(c, "wrong type (expect=%d/%d,got=%d/%d)",
                    OBJ_HASH, OBJ_ENCODING_HT, val->type, val->encoding);
            return C_ERR;
        }
    } else {
        val = createHashObject();
        if (val->encoding != OBJ_ENCODING_HT) {
            hashTypeConvert(val, OBJ_ENCODING_HT);
        }
        dbAdd(c->db, key, val);
    }

    if (size != 0) {
        dict *ht = val->ptr;
        dictExpand(ht, size);
    }

    robj **argv = &c->argv[5]; int argc = c->argc - 5;

    for (int i = 0; i < argc; i += 2) {
        hashTypeSet(val, argv[i]->ptr, argv[i+1]->ptr, HASH_SET_COPY);
    }
    return C_OK;
}

/* RESTORE-ASYNC dict $key $ttlms $maxsize [$elem1 ...] */
static int
restoreAsyncHandleOrReplyTypeDict(client *c, robj *key, long long size) {
    robj *val = lookupKeyWrite(c->db, key);
    if (val != NULL) {
        if (val->type != OBJ_SET || val->encoding != OBJ_ENCODING_HT) {
            asyncMigrationReplyAckErrorFormat(c, "wrong type (expect=%d/%d,got=%d/%d)",
                    OBJ_SET, OBJ_ENCODING_HT, val->type, val->encoding);
            return C_ERR;
        }
    } else {
        val = createSetObject();
        if (val->encoding != OBJ_ENCODING_HT) {
            setTypeConvert(val, OBJ_ENCODING_HT);
        }
        dbAdd(c->db, key, val);
    }

    if (size != 0) {
        dict *ht = val->ptr;
        dictExpand(ht, size);
    }

    robj **argv = &c->argv[5]; int argc = c->argc - 5;

    for (int i = 0; i < argc; i ++) {
        setTypeAdd(val, argv[i]->ptr);
    }
    return C_OK;
}

/* RESTORE-ASYNC zset $key $ttlms $maxsize [$elem1 $score1 ...] */
static int
restoreAsyncHandleOrReplyTypeZSet(client *c, robj *key, long long size) {
    robj **argv = &c->argv[5]; int argc = c->argc - 5;

    double *scores = zmalloc(sizeof(double) * (argc / 2));
    for (int i = 1, j = 0; i < argc; i += 2, j ++) {
        uint64_t u8;
        if (decodeUint64FromRawStringObject(argv[i], &u8) != C_OK) {
            asyncMigrationReplyAckErrorFormat(c, "invalid value of score[%d] (%s)",
                    j, argv[i]->ptr);
            zfree(scores);
            return C_ERR;
        }
        scores[j] = convertRawBitsToDouble(u8);
    }

    robj *val = lookupKeyWrite(c->db, key);
    if (val != NULL) {
        if (val->type != OBJ_ZSET || val->encoding != OBJ_ENCODING_SKIPLIST) {
            asyncMigrationReplyAckErrorFormat(c, "wrong type (expect=%d/%d,got=%d/%d)",
                    OBJ_ZSET, OBJ_ENCODING_SKIPLIST, val->type, val->encoding);
            zfree(scores);
            return C_ERR;
        }
    } else {
        val = createZsetObject();
        if (val->encoding != OBJ_ENCODING_SKIPLIST) {
            zsetConvert(val, OBJ_ENCODING_SKIPLIST);
        }
        dbAdd(c->db, key, val);
    }

    if (size != 0) {
        zset *zs = val->ptr;
        dict *ht = zs->dict;
        dictExpand(ht, size);
    }

    for (int i = 0, j = 0; i < argc; i += 2, j ++) {
        int flags = ZADD_NONE;
        zsetAdd(val, scores[j], argv[i]->ptr, &flags, NULL);
    }
    zfree(scores);
    return C_OK;
}

/* *
 * RESTORE-ASYNC select $db
 *               delete $key
 *               expire $key $ttlms
 *               object $key $ttlms $payload
 *               string $key $ttlms $payload
 *               list   $key $ttlms $maxsize [$elem1 ...]
 *               hash   $key $ttlms $maxsize [$hkey1 $hval1 ...]
 *               dict   $key $ttlms $maxsize [$elem1 ...]
 *               zset   $key $ttlms $maxsize [$elem1 $score1 ...]
 * */
void
restoreAsyncCommand(client *c) {
    if (asyncMigrationClientStatusOrBlock(c, 0) != 0) {
        asyncMigrationReplyAckErrorFormat(c, "the specified DB is being migrated");
        return;
    }

    const char *cmd = "(nil)";
    if (c->argc <= 1) {
        goto bad_arguments_number;
    }
    cmd = c->argv[1]->ptr;

    /* RESTORE-ASYNC select $db */
    if (!strcasecmp(cmd, "select")) {
        if (c->argc != 3) {
            goto bad_arguments_number;
        }
        if (restoreAsyncHandleOrReplySelectDb(c) == C_OK) {
            goto success_common_reply;
        }
        return;
    }

    if (c->argc <= 2) {
        goto bad_arguments_number;
    }
    robj *key = c->argv[2];

    /* RESTORE-ASYNC delete $key */
    if (!strcasecmp(cmd, "delete")) {
        if (c->argc != 3) {
            goto bad_arguments_number;
        }
        if (restoreAsyncHandleOrReplyDeleteKey(c, key) == C_OK) {
            goto success_common_reply;
        }
        return;
    }

    if (c->argc <= 3) {
        goto bad_arguments_number;
    }
    long long ttlms;
    if (getLongLongFromObject(c->argv[3], &ttlms) != C_OK || ttlms < 0) {
        asyncMigrationReplyAckErrorFormat(c, "invalid value of ttlms (%s)",
                c->argv[3]->ptr);
        return;
    }

    /* RESTORE-ASYNC expire $key $ttlms */
    if (!strcasecmp(cmd, "expire")) {
        if (c->argc != 4) {
            goto bad_arguments_number;
        }
        if (restoreAsyncHandleOrReplyExpireKey(c, key) == C_OK) {
            goto success_common_ttlms;
        }
        return;
    }

    /* RESTORE-ASYNC object $key $ttlms $payload */
    if (!strcasecmp(cmd, "object")) {
        if (c->argc != 5) {
            goto bad_arguments_number;
        }
        if (restoreAsyncHandleOrReplyTypeObject(c, key) == C_OK) {
            goto success_common_ttlms;
        }
        return;
    }

    /* RESTORE-ASYNC string $key $ttlms $payload */
    if (!strcasecmp(cmd, "string")) {
        if (c->argc != 5) {
            goto bad_arguments_number;
        }
        if (restoreAsyncHandleOrReplyTypeString(c, key) == C_OK) {
            goto success_common_ttlms;
        }
        return;
    }

    if (c->argc <= 4) {
        goto bad_arguments_number;
    }
    long long maxsize;
    if (getLongLongFromObject(c->argv[4], &maxsize) != C_OK || maxsize < 0) {
        asyncMigrationReplyAckErrorFormat(c, "invalid value of maxsize (%s)",
                c->argv[4]->ptr);
        return;
    }

    /* RESTORE-ASYNC list $key $ttlms $maxsize [$elem1 ...] */
    if (!strcasecmp(cmd, "list")) {
        if (c->argc <= 5) {
            goto bad_arguments_number;
        }
        if (restoreAsyncHandleOrReplyTypeList(c, key) == C_OK) {
            goto success_common_ttlms;
        }
        return;
    }

    /* RESTORE-ASYNC hash $key $ttlms $maxsize [$hkey1 $hval1 ...] */
    if (!strcasecmp(cmd, "hash")) {
        if (c->argc <= 5 || (c->argc - 5) % 2 != 0) {
            goto bad_arguments_number;
        }
        if (restoreAsyncHandleOrReplyTypeHash(c, key, maxsize) == C_OK) {
            goto success_common_ttlms;
        }
        return;
    }

    /* RESTORE-ASYNC dict $key $ttlms $maxsize [$elem1 ...] */
    if (!strcasecmp(cmd, "dict")) {
        if (c->argc <= 5) {
            goto bad_arguments_number;
        }
        if (restoreAsyncHandleOrReplyTypeDict(c, key, maxsize) == C_OK) {
            goto success_common_ttlms;
        }
        return;
    }

    /* RESTORE-ASYNC zset $key $ttlms $maxsize [$elem1 $score1 ...] */
    if (!strcasecmp(cmd, "zset")) {
        if (c->argc <= 5 || (c->argc - 5) % 2 != 0) {
            goto bad_arguments_number;
        }
        if (restoreAsyncHandleOrReplyTypeZSet(c, key, maxsize) == C_OK) {
            goto success_common_ttlms;
        }
        return;
    }

    asyncMigrationReplyAckErrorFormat(c, "unknown command (cmd=%s,argc=%d)",
            cmd, c->argc);
    return;

success_common_ttlms:
    if (ttlms != 0) {
        setExpire(c, c->db, key, mstime() + ttlms);
    } else {
        removeExpire(c->db, key);
    }
    signalModifiedKey(c->db, key);
    server.dirty ++;

success_common_reply:
    asyncMigrationReplyAckString(c, "OK");
    return;

bad_arguments_number:
    asyncMigrationReplyAckErrorFormat(c, "invalid arguments (cmd=%s,argc=%d)",
            cmd, c->argc);
    return;
}

/* ============================ TODO == TODO == TODO ======================================= */

int *migrateAsyncGetKeys(struct redisCommand *cmd, robj **argv, int argc, int *numkeys) {
    /* TODO */
    (void)cmd;
    (void)argv;
    (void)argc;
    (void)numkeys;
    return NULL;
}

void migrateAsyncStatusCommand(client *c) {
    /* TODO */
    (void)c;
}

int *restoreAsyncGetKeys(struct redisCommand *cmd, robj **argv, int argc, int *numkeys) {
    /* TODO */
    (void)cmd;
    (void)argv;
    (void)argc;
    (void)numkeys;
    return NULL;
}

void restoreAsyncAckCommand(client *c) {
    /* TODO */
    (void)c;
}
