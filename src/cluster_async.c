#include "server.h"

// ==================== Iterators: singleObjectIterator =====================

#define STAGE_PREPARE 0
#define STAGE_PAYLOAD 1
#define STAGE_CHUNKED 2
#define STAGE_PEXPIRE 3
#define STAGE_DONE 4

// The definition of L1-Iterator.
typedef struct {
    int stage;  // The current state of the state machine.
    robj* key;  // The key/value pair that will be serialized.
    robj* obj;
    mstime_t expire;       // The expire time in ms, or -1 if no expire time.
    unsigned long cursor;  // Used to serialize Hash/Set object.
    unsigned long lindex;  // Used to serialize List object.
    unsigned long zindex;  // Used to serialize ZSet object.
} singleObjectIterator;

// Create a L1-Iterator to hold the key and increase its refcount.
static singleObjectIterator* createSingleObjectIterator(robj* key) {
    singleObjectIterator* it = zmalloc(sizeof(*it));
    it->stage = STAGE_PREPARE;
    it->key = key;
    incrRefCount(it->key);
    it->obj = NULL;
    it->expire = 0;
    it->cursor = 0;
    it->lindex = 0;
    it->zindex = 0;
    return it;
}

extern void decrRefCountLazyfree(robj* obj);

// Release a L1-Iterator and release its key/value's refcount.
static void freeSingleObjectIterator(singleObjectIterator* it) {
    if (it->obj != NULL) {
        decrRefCountLazyfree(it->obj);
    }
    decrRefCount(it->key);
    zfree(it);
}

static void freeSingleObjectIteratorVoid(void* it) {
    freeSingleObjectIterator(it);
}

static int singleObjectIteratorHasNext(singleObjectIterator* it) {
    return it->stage != STAGE_DONE;
}

// Estimate the number of RESTORE-ASYNC commands will be generated for the
// specified object with the given maxbulks.
static size_t estimateNumberOfRestoreCommandsObject(robj* obj,
                                                    size_t maxbulks) {
    size_t numbulks = 0;
    switch (obj->type) {
    case OBJ_LIST:
        if (obj->encoding == OBJ_ENCODING_QUICKLIST) {
            numbulks = listTypeLength(obj);
        }
        break;
    case OBJ_HASH:
        if (obj->encoding == OBJ_ENCODING_HT) {
            numbulks = hashTypeLength(obj) * 2;
        }
        break;
    case OBJ_SET:
        if (obj->encoding == OBJ_ENCODING_HT) {
            numbulks = setTypeSize(obj);
        }
        break;
    case OBJ_ZSET:
        if (obj->encoding == OBJ_ENCODING_SKIPLIST) {
            numbulks = zsetLength(obj) * 2;
        }
        break;
    }

    // case numbulks == 0:
    //      The object's encoding type is too complex.
    //      For example, a zip-compressed set or list.
    // case numbulks <= maxbulks:
    //      The specified input object is too small.
    //
    // 1 x RESTORE-PAYLOAD command will be generated for these cases.
    if (numbulks <= maxbulks) {
        return 1;
    }

    // Object is big enough, and its serialization process will be split into
    // n x RESTORE-CHUNKED + 1 x RESTORE-PEXPIRE commands.
    return 1 + (numbulks + maxbulks - 1) / maxbulks;
}

// Estimate the number of RESTORE-ASYNC commands will be generated for the
// specified key in the given database, or return 0 if the key doesn't exist.
// Unlike estimateNumberOfRestoreCommandsObject(), this function also counts
// the precursor RESTORE-ASYNC DELETE command.
static size_t estimateNumberOfRestoreCommands(redisDb* db, robj* key,
                                              size_t maxbulks) {
    robj* obj = lookupKeyRead(db, key);
    if (obj == NULL) {
        return 0;
    }
    // For tiny or zip-compressed objects:
    //  = 1 x RESTORE-PREPARE + 1 x RESTORE-PAYLOAD
    // Otherwise, for normal cases:
    //  = 1 x RESTORE-PAYLOAD + n x RESTORE-CHUNKED + 1 x RESTORE-PEXPIRE
    return 1 + estimateNumberOfRestoreCommandsObject(obj, maxbulks);
}

static migrateAsyncClient* getMigrateAsyncClient(int db);

// State Machine:
//                    (1)
//          +--------------------------------------+
//          |                                      |
//          |         (2)                          V
//      STAGE_PREPARE ---> STAGE_PAYLOAD ---> STAGE_DONE
//          |                                      A
//          |         (3)                          |
//          +------------> STAGE_CHUNKED ---> STAGE_PEXPIRE
//                           A       |
//                           |       V
//                           +-------+
//
// (1) If the specified key doesn't exist. Usually cased by time expiration.
// (2) If the object is small enough or has a complex encoding type.
// (3) Normal case.
static int singleObjectIteratorNextStagePrepare(client* c,
                                                singleObjectIterator* it,
                                                size_t maxbulks) {
    serverAssert(it->stage == STAGE_PREPARE);

    robj* key = it->key;
    robj* obj = lookupKeyRead(c->db, key);

    // If the specified key doesn't exist.
    if (obj == NULL) {
        it->stage = STAGE_DONE;
        return 0;
    }

    // Keep the refcount of the object and record its expire time.
    it->obj = obj;
    incrRefCount(it->obj);
    it->expire = getExpire(c->db, key);

    int sending_messages = 0;

    migrateAsyncClient* ac = getMigrateAsyncClient(c->db->id);

    // If current client belongs to migrateAsyncClient, then:
    //      1. Send RESTORE-ASYNC-AUTH   to verify password.
    //      2. Send RESTORE-ASYNC-SELECT to change database.
    if (ac->c == c) {
        if (ac->authenticated == 0) {
            ac->authenticated = 1;
            if (server.requirepass != NULL) {
                // RESTORE-ASYNC-AUTH $passwd
                addReplyMultiBulkLen(c, 2);
                addReplyBulkCString(c, "RESTORE-ASYNC-AUTH");
                addReplyBulkCString(c, server.requirepass);
                sending_messages++;
            }
            do {
                // RESTORE-ASYNC-SELECT $db
                addReplyMultiBulkLen(c, 2);
                addReplyBulkCString(c, "RESTORE-ASYNC-SELECT");
                addReplyBulkLongLong(c, c->db->id);
                sending_messages++;
            } while (0);
        }
    }

    // Send the RESTORE-ASYNC DELETE to the target instance to remove the
    // conflicting key before the migration starts.
    do {
        // RESTORE-ASYNC delete $key
        addReplyMultiBulkLen(c, 3);
        addReplyBulkCString(c, "RESTORE-ASYNC");
        addReplyBulkCString(c, "delete");
        addReplyBulk(c, key);
        sending_messages++;
    } while (0);

    size_t n = estimateNumberOfRestoreCommandsObject(obj, maxbulks);
    if (n != 1) {
        it->stage = STAGE_CHUNKED;
    } else {
        it->stage = STAGE_PAYLOAD;
    }
    return sending_messages;
}

extern void createDumpPayload(rio* payload, robj* o);

// State Machine:
//
//          +--------------------------------------+
//          |                                      |
//          |                            (4)       V
//      STAGE_PREPARE ---> STAGE_PAYLOAD ---> STAGE_DONE
//          |                                      A
//          |                                      |
//          +------------> STAGE_CHUNKED ---> STAGE_PEXPIRE
//                           A       |
//                           |       V
//                           +-------+
//
// (4) Serialize the specified key/value pair, and then move to STAGE_DONE.
static int singleObjectIteratorNextStagePayload(client* c,
                                                singleObjectIterator* it) {
    serverAssert(it->stage == STAGE_PAYLOAD);

    robj* key = it->key;
    robj* obj = it->obj;

    mstime_t ttlms = 0;
    if (it->expire != -1) {
        ttlms = it->expire - mstime();
        if (ttlms < 1) {
            ttlms = 1;
        }
    }

    // case obj->type != string:
    //      Serialize the object with DUMP format.
    // case obj->type == string:
    //      Using string format directly for improved performance.
    if (obj->type != OBJ_STRING) {
        rio payload;
        createDumpPayload(&payload, obj);
        do {
            // RESTORE-ASYNC object $key $ttlms $payload
            addReplyMultiBulkLen(c, 5);
            addReplyBulkCString(c, "RESTORE-ASYNC");
            addReplyBulkCString(c, "object");
            addReplyBulk(c, key);
            addReplyBulkLongLong(c, ttlms);
            addReplyBulkSds(c, payload.io.buffer.ptr);
        } while (0);
    } else {
        do {
            // RESTORE-ASYNC string $key $ttlms $payload
            addReplyMultiBulkLen(c, 5);
            addReplyBulkCString(c, "RESTORE-ASYNC");
            addReplyBulkCString(c, "string");
            addReplyBulk(c, key);
            addReplyBulkLongLong(c, ttlms);
            addReplyBulk(c, obj);
        } while (0);
    }

    it->stage = STAGE_DONE;
    return 1;
}

static int singleObjectIteratorNextStageChunkedTypeList(
    client* c, singleObjectIterator* it, robj* key, robj* obj, mstime_t ttlms,
    size_t maxbulks, int* psending_messages) {
    serverAssert(obj->type == OBJ_LIST);
    serverAssert(obj->encoding == OBJ_ENCODING_QUICKLIST);

    // Send the list's length in the first chunked data.
    int first = it->lindex == 0;

    unsigned long llen = listTypeLength(obj);
    if (it->lindex >= llen) {
        return 1;
    }

    unsigned long step = llen - it->lindex;
    if (step > maxbulks) {
        step = maxbulks;
    }
    (*psending_messages)++;

    long seek;
    if (it->lindex <= llen / 2) {
        // Seek from the head.
        seek = (long)it->lindex;
    } else {
        // Seek from the tail.
        seek = (long)it->lindex - llen;
    }

    // RESTORE-ASYNC list $key $ttlms $maxsize [$arg1 ...]
    addReplyMultiBulkLen(c, 5 + step);
    addReplyBulkCString(c, "RESTORE-ASYNC");
    addReplyBulkCString(c, "list");
    addReplyBulk(c, key);
    addReplyBulkLongLong(c, ttlms);
    addReplyBulkLongLong(c, first ? llen : 0);

    listTypeIterator* li = listTypeInitIterator(obj, seek, LIST_TAIL);
    for (size_t i = 0; i < step; i++) {
        listTypeEntry entry;
        listTypeNext(li, &entry);
        quicklistEntry* qe = &(entry.entry);
        if (qe->value) {
            addReplyBulkCBuffer(c, qe->value, qe->sz);
        } else {
            addReplyBulkLongLong(c, qe->longval);
        }
        it->lindex++;
    }
    listTypeReleaseIterator(li);
    return 0;
}

// Declare an append-only vector.
typedef struct {
    size_t cap, len;
    void** buf;
} vector;

static vector* vectorInit(size_t cap) {
    vector* v = zmalloc(sizeof(*v));
    v->len = 0, v->cap = cap;
    if (v->cap != 0) {
        v->buf = zmalloc(sizeof(v->buf[0]) * v->cap);
    } else {
        v->buf = NULL;
    }
    return v;
}

static void vectorFree(vector* v) {
    zfree(v->buf);
    zfree(v);
}

static void vectorPush(vector* v, void* value) {
    if (v->cap == v->len) {
        v->cap = (v->cap != 0) ? v->cap * 4 : 1024;
        v->buf = zrealloc(v->buf, sizeof(v->buf[0]) * v->cap);
    }
    v->buf[v->len++] = value;
}

static uint64_t doubleToLong(double value) {
    union {
        double d;
        uint64_t u;
    } fp;
    fp.d = value;
    return intrev64ifbe(fp.u);
}

static double longToDouble(uint64_t value) {
    union {
        double d;
        uint64_t u;
    } fp;
    fp.u = intrev64ifbe(value);
    return fp.d;
}

static int longToDoubleFromObject(robj* o, double* p) {
    if (sdsEncodedObject(o) && sdslen(o->ptr) == sizeof(uint64_t)) {
        *p = longToDouble(*(uint64_t*)(o->ptr));
        return C_OK;
    }
    return C_ERR;
}

extern zskiplistNode* zslGetElementByRank(zskiplist* zsl, unsigned long rank);

static int singleObjectIteratorNextStageChunkedTypeZSet(
    client* c, singleObjectIterator* it, robj* key, robj* obj, mstime_t ttlms,
    size_t maxbulks, int* psending_messages) {
    serverAssert(obj->type == OBJ_ZSET);
    serverAssert(obj->encoding == OBJ_ENCODING_SKIPLIST);

    // Send the zset's length in the first chunked data.
    int first = it->zindex == 0, done = 0;
    vector* v = vectorInit(maxbulks * 2);

    // Send fields in revese order for better performance due to issue #3912.
    long long rank = (long long)zsetLength(obj) - it->zindex;
    zskiplist* zsl = ((zset*)obj->ptr)->zsl;
    zskiplistNode* node = (rank >= 1) ? zslGetElementByRank(zsl, rank) : NULL;

    size_t maxlen = maxbulks / 2;
    do {
        if (node != NULL) {
            vectorPush(v, node);
            node = node->backward;
            it->zindex++;
        } else {
            done = 1;
        }
    } while (!done && v->len < maxlen);

    if (v->len == 0) {
        goto exit;
    }
    (*psending_messages)++;

    // RESTORE-ASYNC zset $key $ttlms $maxsize [$arg1 ...]
    addReplyMultiBulkLen(c, 5 + v->len * 2);
    addReplyBulkCString(c, "RESTORE-ASYNC");
    addReplyBulkCString(c, "zset");
    addReplyBulk(c, key);
    addReplyBulkLongLong(c, ttlms);
    addReplyBulkLongLong(c, first ? zsetLength(obj) : 0);
    for (size_t i = 0; i < v->len; i++) {
        zskiplistNode* node = v->buf[i];
        addReplyBulkCBuffer(c, node->ele, sdslen(node->ele));
        uint64_t u64 = doubleToLong(node->score);
        addReplyBulkCBuffer(c, &u64, sizeof(u64));
    }

exit:
    vectorFree(v);
    return done;
}

static void singleObjectIteratorScanCallback(void* data, const dictEntry* de) {
    void** pd = (void**)data;
    vector* v = pd[0];
    vectorPush(v, (void*)de);
}

static int singleObjectIteratorNextStageChunkedTypeHash(
    client* c, singleObjectIterator* it, robj* key, robj* obj, mstime_t ttlms,
    size_t maxbulks, int* psending_messages) {
    serverAssert(obj->type == OBJ_HASH);
    serverAssert(obj->encoding == OBJ_ENCODING_HT);

    // Send the hash's size in the first chunked data.
    int first = it->cursor == 0, done = 0;
    vector* v = vectorInit(maxbulks * 2);

    int loop = maxbulks * 10;
    if (loop < 100) {
        loop = 100;
    }
    void* pd[] = {v};

    // Call dictScan on hash table and keep all scanned entries.
    size_t maxlen = maxbulks / 2;
    do {
        it->cursor = dictScan(obj->ptr, it->cursor,
                              singleObjectIteratorScanCallback, NULL, pd);
        if (it->cursor == 0) {
            done = 1;
        }
    } while (!done && v->len < maxlen && (--loop) >= 0);

    if (v->len == 0) {
        goto exit;
    }
    (*psending_messages)++;

    // RESTORE-ASYNC hash $key $ttlms $maxsize [$arg1 ...]
    addReplyMultiBulkLen(c, 5 + v->len * 2);
    addReplyBulkCString(c, "RESTORE-ASYNC");
    addReplyBulkCString(c, "hash");
    addReplyBulk(c, key);
    addReplyBulkLongLong(c, ttlms);
    addReplyBulkLongLong(c, first ? hashTypeLength(obj) : 0);
    for (size_t i = 0; i < v->len; i++) {
        dictEntry* entry = v->buf[i];
        sds skey = dictGetKey(entry);
        addReplyBulkCBuffer(c, skey, sdslen(skey));
        sds sval = dictGetVal(entry);
        addReplyBulkCBuffer(c, sval, sdslen(sval));
    }

exit:
    vectorFree(v);
    return done;
}

static int singleObjectIteratorNextStageChunkedTypeSet(
    client* c, singleObjectIterator* it, robj* key, robj* obj, mstime_t ttlms,
    size_t maxbulks, int* psending_messages) {
    serverAssert(obj->type == OBJ_SET);
    serverAssert(obj->encoding == OBJ_ENCODING_HT);

    // Send the set's size in the first chunked data.
    int first = it->cursor == 0, done = 0;
    vector* v = vectorInit(maxbulks * 2);

    int loop = maxbulks * 10;
    if (loop < 100) {
        loop = 100;
    }
    void* pd[] = {v};

    // Call dictScan on hash table and keep all scanned entries.
    size_t maxlen = maxbulks;
    do {
        it->cursor = dictScan(obj->ptr, it->cursor,
                              singleObjectIteratorScanCallback, NULL, pd);
        if (it->cursor == 0) {
            done = 1;
        }
    } while (!done && v->len < maxlen && (--loop) >= 0);

    if (v->len == 0) {
        goto exit;
    }
    (*psending_messages)++;

    // RESTORE-ASYNC set  $key $ttlms $maxsize [$arg1 ...]
    addReplyMultiBulkLen(c, 5 + v->len);
    addReplyBulkCString(c, "RESTORE-ASYNC");
    addReplyBulkCString(c, "set");
    addReplyBulk(c, key);
    addReplyBulkLongLong(c, ttlms);
    addReplyBulkLongLong(c, first ? setTypeSize(obj) : 0);
    for (size_t i = 0; i < v->len; i++) {
        dictEntry* entry = v->buf[i];
        sds skey = dictGetKey(entry);
        addReplyBulkCBuffer(c, skey, sdslen(skey));
    }

exit:
    vectorFree(v);
    return done;
}

// State Machine:
//
//          +--------------------------------------+
//          |                                      |
//          |                                      V
//      STAGE_PREPARE ---> STAGE_PAYLOAD ---> STAGE_DONE
//          |                                      A
//          |                            (5)       |
//          +------------> STAGE_CHUNKED ---> STAGE_PEXPIRE
//                           A       |
//                           |  (5)  V
//                           +-------+
//
// (5) Serialize the specified key/value pair, and then move to STAGE_PEXPIRE.
static int singleObjectIteratorNextStageChunked(client* c,
                                                singleObjectIterator* it,
                                                mstime_t timeout,
                                                size_t maxbulks) {
    serverAssert(it->stage == STAGE_CHUNKED);

    robj* key = it->key;
    robj* obj = it->obj;

    // Set a temporary ttl for the specified key/value pair.
    mstime_t ttlms = timeout * 3;
    if (ttlms < 1000) {
        ttlms = 1000;
    }

    int done, sending_messages = 0;
    switch (obj->type) {
    case OBJ_LIST:
        done = singleObjectIteratorNextStageChunkedTypeList(
            c, it, key, obj, ttlms, maxbulks, &sending_messages);
        break;
    case OBJ_ZSET:
        done = singleObjectIteratorNextStageChunkedTypeZSet(
            c, it, key, obj, ttlms, maxbulks, &sending_messages);
        break;
    case OBJ_HASH:
        done = singleObjectIteratorNextStageChunkedTypeHash(
            c, it, key, obj, ttlms, maxbulks, &sending_messages);
        break;
    case OBJ_SET:
        done = singleObjectIteratorNextStageChunkedTypeSet(
            c, it, key, obj, ttlms, maxbulks, &sending_messages);
        break;
    default:
        serverPanic("unknown object type = %d", obj->type);
    }

    if (done) {
        it->stage = STAGE_PEXPIRE;
    }
    return sending_messages;
}

// State Machine:
//
//          +--------------------------------------+
//          |                                      |
//          |                                      V
//      STAGE_PREPARE ---> STAGE_PAYLOAD ---> STAGE_DONE
//          |                                      A
//          |                                      | (6)
//          +------------> STAGE_CHUNKED ---> STAGE_PEXPIRE
//                           A       |
//                           |       V
//                           +-------+
//
// (6) Correct the ttl or remove the temporary ttl and then move to STAGE_DONE.
static int singleObjectIteratorNextStagePExpire(client* c,
                                                singleObjectIterator* it) {
    serverAssert(it->stage == STAGE_PEXPIRE);
    robj* key = it->key;

    mstime_t ttlms = 0;
    if (it->expire != -1) {
        ttlms = it->expire - mstime();
        if (ttlms < 1) {
            ttlms = 1;
        }
    }

    do {
        // RESTORE-ASYNC expire $key $ttlms
        addReplyMultiBulkLen(c, 4);
        addReplyBulkCString(c, "RESTORE-ASYNC");
        addReplyBulkCString(c, "expire");
        addReplyBulk(c, key);
        addReplyBulkLongLong(c, ttlms);
    } while (0);

    it->stage = STAGE_DONE;
    return 1;
}

// State Machine:
//
//          +--------------------------------------+
//          |                                      |
//          |                                      V
//      STAGE_PREPARE ---> STAGE_PAYLOAD ---> STAGE_DONE
//          |                                      A
//          |                                      |
//          +------------> STAGE_CHUNKED ---> STAGE_PEXPIRE
//                           A       |
//                           |       V
//                           +-------+
//
// The entry point of the state machine.
// This function returns the number of RESTORE-ASYNC commands that is generated
// and will be serialized into client's sending buffer.
static int singleObjectIteratorNext(client* c, singleObjectIterator* it,
                                    mstime_t timeout, size_t maxbulks) {
    switch (it->stage) {
    case STAGE_PREPARE:
        return singleObjectIteratorNextStagePrepare(c, it, maxbulks);
    case STAGE_PAYLOAD:
        return singleObjectIteratorNextStagePayload(c, it);
    case STAGE_CHUNKED:
        return singleObjectIteratorNextStageChunked(c, it, timeout, maxbulks);
    case STAGE_PEXPIRE:
        return singleObjectIteratorNextStagePExpire(c, it);
    case STAGE_DONE:
        return 0;
    default:
        serverPanic("unknown stage=%d of singleObjectIterator", it->stage);
    }
}

// Dump the metrics of the given L1-Iterator.
static void singleObjectIteratorStatus(client* c, singleObjectIterator* it) {
    if (it == NULL) {
        addReply(c, shared.nullmultibulk);
        return;
    }
    void* ptr = addDeferredMultiBulkLength(c);
    int total = 0;

    total++;
    addReplyBulkCString(c, "key");
    addReplyBulk(c, it->key);

    total++;
    addReplyBulkCString(c, "object_type");
    addReplyBulkLongLong(c, it->obj == NULL ? -1 : it->obj->type);

    total++;
    addReplyBulkCString(c, "object_encoding");
    addReplyBulkLongLong(c, it->obj == NULL ? -1 : it->obj->encoding);

    total++;
    addReplyBulkCString(c, "stage");
    addReplyBulkLongLong(c, it->stage);

    total++;
    addReplyBulkCString(c, "expire");
    addReplyBulkLongLong(c, it->expire);

    total++;
    addReplyBulkCString(c, "cursor");
    addReplyBulkLongLong(c, it->cursor);

    total++;
    addReplyBulkCString(c, "lindex");
    addReplyBulkLongLong(c, it->lindex);

    total++;
    addReplyBulkCString(c, "zindex");
    addReplyBulkLongLong(c, it->zindex);

    setDeferredMultiBulkLength(c, ptr, total * 2);
}

// ==================== Iterators: batchedObjectIterator ====================

// The definition of L0-Iterator.
typedef struct {
    mstime_t timeout;     // Timeout for RTT.
    dict* keys;           // The keys that will be migrated.
    list* iterator_list;  // The L1-Iterators that will be dispatched.
    list* finished_keys;  // The keys that have been migrated and will be
                          // removed atomically once the entire batch finished.
    size_t maxbulks;
    size_t delivered_messages;
    size_t estimated_messages;
} batchedObjectIterator;

// Create a L0-Iterator.
static batchedObjectIterator* createBatchedObjectIterator(mstime_t timeout) {
    batchedObjectIterator* it = zmalloc(sizeof(*it));
    it->timeout = timeout;
    it->keys = dictCreate(&objectKeyPointerValueDictType, NULL);
    it->iterator_list = listCreate();
    listSetFreeMethod(it->iterator_list, freeSingleObjectIteratorVoid);
    it->finished_keys = listCreate();
    listSetFreeMethod(it->finished_keys, decrRefCountVoid);
    it->maxbulks = server.migrate_async_message_limit;
    it->delivered_messages = 0;
    it->estimated_messages = 0;
    return it;
}

// Release a L0-Iterator and release all related resouces respectively.
static void freeBatchedObjectIterator(batchedObjectIterator* it) {
    dictRelease(it->keys);
    listRelease(it->iterator_list);
    listRelease(it->finished_keys);
    zfree(it);
}

static int batchedObjectIteratorHasNext(batchedObjectIterator* it) {
    list* ll = it->iterator_list;
    while (listLength(ll) != 0) {
        listNode* head = listFirst(ll);
        singleObjectIterator* sp = listNodeValue(head);
        if (singleObjectIteratorHasNext(sp)) {
            return 1;
        }
        if (sp->obj != NULL) {
            incrRefCount(sp->key);
            listAddNodeTail(it->finished_keys, sp->key);
        }
        listDelNode(ll, head);
    }
    return 0;
}

static int batchedObjectIteratorNext(client* c, batchedObjectIterator* it) {
    list* ll = it->iterator_list;
    if (listLength(ll) != 0) {
        listNode* head = listFirst(ll);
        singleObjectIterator* sp = listNodeValue(head);
        return singleObjectIteratorNext(c, sp, it->timeout, it->maxbulks);
    }
    return 0;
}

// Add the specified key to current batch if it doesn't exsit yet.
static int batchedObjectIteratorAddKey(redisDb* db, batchedObjectIterator* it,
                                       robj* key) {
    if (dictAdd(it->keys, key, NULL) != DICT_OK) {
        return 0;
    }
    incrRefCount(key);

    listAddNodeTail(it->iterator_list, createSingleObjectIterator(key));
    it->estimated_messages +=
        estimateNumberOfRestoreCommands(db, key, it->maxbulks);
    return 1;
}

// Dump the metrics of the given L0-Iterator.
static void batchedObjectIteratorStatus(client* c, batchedObjectIterator* it) {
    if (it == NULL) {
        addReply(c, shared.nullmultibulk);
        return;
    }
    void* ptr = addDeferredMultiBulkLength(c);
    int total = 0;

    total++;
    addReplyBulkCString(c, "keys");
    addReplyMultiBulkLen(c, 2);
    addReplyBulkLongLong(c, dictSize(it->keys));
    do {
        addReplyMultiBulkLen(c, dictSize(it->keys));
        dictIterator* di = dictGetIterator(it->keys);
        dictEntry* entry;
        while ((entry = dictNext(di)) != NULL) {
            robj* key = dictGetKey(entry);
            addReplyBulkCBuffer(c, key->ptr, sdslen(key->ptr));
        }
        dictReleaseIterator(di);
    } while (0);

    total++;
    addReplyBulkCString(c, "timeout");
    addReplyBulkLongLong(c, it->timeout);

    total++;
    addReplyBulkCString(c, "maxbulks");
    addReplyBulkLongLong(c, it->maxbulks);

    total++;
    addReplyBulkCString(c, "estimated_messages");
    addReplyBulkLongLong(c, it->estimated_messages);

    total++;
    addReplyBulkCString(c, "delivered_messages");
    addReplyBulkLongLong(c, it->delivered_messages);

    total++;
    addReplyBulkCString(c, "finished_keys");
    addReplyBulkLongLong(c, listLength(it->finished_keys));

    total++;
    addReplyBulkCString(c, "iterator_list");
    addReplyMultiBulkLen(c, 2);
    addReplyBulkLongLong(c, listLength(it->iterator_list));
    do {
        list* ll = it->iterator_list;
        if (listLength(ll) != 0) {
            listNode* head = listFirst(ll);
            singleObjectIteratorStatus(c, listNodeValue(head));
        } else {
            singleObjectIteratorStatus(c, NULL);
        }
    } while (0);

    setDeferredMultiBulkLength(c, ptr, total * 2);
}

// ==================== Clients for Asynchronous Migration ==================

// Get the migrateAsyncClient instance that belongs to the given database.
static migrateAsyncClient* getMigrateAsyncClient(int db) {
    return &server.migrate_async_clients[db];
}

// Wakeup the clients that is waiting on the specified migrateAsyncClient.
// case errmsg != NULL:
//      Client will be notified with RespErr.
// case errmsg == NULL:
//      Client will be notified with RespInt. (# of migrated keys)
static void migrateAsyncClientInterrupt(migrateAsyncClient* ac,
                                        const char* errmsg) {
    batchedObjectIterator* it = ac->batched_iterator;
    long ret = (it != NULL) ? (long)listLength(it->finished_keys) : -1;

    list* ll = ac->blocked_clients;
    while (listLength(ll) != 0) {
        listNode* head = listFirst(ll);
        client* c = listNodeValue(head);
        serverAssert(c->migrate_async_list == ll);

        if (errmsg != NULL) {
            addReplyError(c, errmsg);
        } else {
            addReplyLongLong(c, ret);
        }

        c->migrate_async_list = NULL;
        listDelNode(ll, head);

        unblockClient(c);
    }
}

// NOTE: Ensure it's only called by unblockClient() in blocked.c.
// Remove the specified client from its waiting list.
void unblockClientFromMigrateAsync(client* c) {
    list* ll = c->migrate_async_list;
    if (ll != NULL) {
        listNode* node = listSearchKey(ll, c);
        serverAssert(node != NULL);

        c->migrate_async_list = NULL;
        listDelNode(ll, node);
    }
}

// NOTE: Ensure it's only called by freeClient() in networking.c.
// Cancel and release an migrateAsyncClient due to various reasons.
void releaseClientFromMigrateAsync(client* c) {
    migrateAsyncClient* ac = getMigrateAsyncClient(c->db->id);
    serverAssert(ac->c == c);

    batchedObjectIterator* it = ac->batched_iterator;

    int db = c->db->id;

    serverLog(
        LL_WARNING,
        "migrate_async[%d]: release connection %s:%d (DB=%d): "
        "pending_messages(%lld), blocked_clients(%ld), iterator_list(%ld), "
        "timeout(%lldms), since_lastuse(%lldms)",
        ac->c->fd, ac->host, ac->port, db, ac->pending_messages,
        (long)listLength(ac->blocked_clients),
        (it != NULL) ? (long)listLength(it->iterator_list) : -1, ac->timeout,
        mstime() - ac->lastuse);

    migrateAsyncClientInterrupt(ac, "interrupted: released connection");

    sdsfree(ac->host);
    if (it != NULL) {
        freeBatchedObjectIterator(it);
    }
    listRelease(ac->blocked_clients);

    c->flags &= ~CLIENT_MIGRATE_ASYNC;

    memset(ac, 0, sizeof(*ac));
}

// Cancel the migration operation and wake up all blocked clients.
static int migrateAsyncClientCancelErrorFormat(int db, const char* fmt, ...) {
    migrateAsyncClient* ac = getMigrateAsyncClient(db);
    if (ac->c == NULL) {
        return 0;
    }
    va_list ap;
    va_start(ap, fmt);
    sds errmsg = sdscatvprintf(sdsempty(), fmt, ap);
    va_end(ap);

    serverLog(LL_WARNING,
              "migrate_async[%d]: release connection %s:%d (DB=%d) (%s)",
              ac->c->fd, ac->host, ac->port, db, errmsg);

    // Wake up the blocked clients with the specified error message.
    migrateAsyncClientInterrupt(ac, errmsg);

    // Call freeClient() to release the migration connection.
    // This operation will trigger releaseClientFromMigrateAsync() to destroy
    // the migrateAsyncClient struct and release all related resources.
    freeClient(ac->c);

    sdsfree(errmsg);

    serverAssert(ac->c == NULL);
    serverAssert(ac->batched_iterator == NULL);
    return 1;
}

// Close the previous client and dial a new one to the target instance, possibly
// return a cached one if the target doesn't change.
static migrateAsyncClient* migrateAsyncClientInit(int db, sds host, int port,
                                                  mstime_t timeout) {
    migrateAsyncClient* ac = getMigrateAsyncClient(db);
    if (ac->c != NULL) {
        // Check if we have an already cached socket for given host:port.
        if (ac->port == port && !strcmp(ac->host, host)) {
            return ac;
        }
    }

    // Dial a new connection to host:port.
    int fd = anetTcpNonBlockConnect(server.neterr, host, port);
    if (fd == -1) {
        serverLog(LL_WARNING,
                  "migrate_async: anetTcpNonBlockConnect %s:%d (DB=%d) (%s)",
                  host, port, db, server.neterr);
        return NULL;
    }

    anetEnableTcpNoDelay(NULL, fd);

    // Check if it connects within 10ms.
    int wait = timeout;
    if (wait > 10) {
        wait = 10;
    }
    if ((aeWait(fd, AE_WRITABLE, wait) & AE_WRITABLE) == 0) {
        serverLog(LL_WARNING,
                  "migrate_async: aeWait %s:%d (DB=%d) (io error or timeout)",
                  host, port, db);
        close(fd);
        return NULL;
    }

    // Create a new client struct to hold the socket.
    client* c = createClient(fd);
    if (c == NULL) {
        serverLog(LL_WARNING, "migrate_async: createClient %s:%d (DB=%d) (%s)",
                  host, port, db, server.neterr);
        return NULL;
    }

    // Change the database.
    if (selectDb(c, db) != C_OK) {
        serverLog(LL_WARNING,
                  "migrate_async: selectDb %s:%d (DB=%d) (invalid DB index)",
                  host, port, db);
        freeClient(c);
        return NULL;
    }

    // Mark this client as authenticated.
    // That is, the responded ack can be processed without authentication.
    c->flags |= CLIENT_MIGRATE_ASYNC;
    c->authenticated = 1;

    // Cancel and release the previous client.
    migrateAsyncClientCancelErrorFormat(
        db, "interrupted: replaced by %s:%d (DB=%d)", host, port, db);

    ac->c = c;
    ac->host = sdsdup(host);
    ac->port = port;
    ac->authenticated = 0;
    ac->timeout = timeout;
    ac->lastuse = mstime();
    ac->pending_messages = 0;
    ac->blocked_clients = listCreate();
    ac->batched_iterator = NULL;
    serverLog(LL_WARNING, "migrate_async[%d]: connect to %s:%d (DB=%d) OK", fd,
              host, port, db);
    return ac;
}

// Check if current database is being migrated.
static int migrateAsyncClientStatusOrBlock(client* c, int block) {
    migrateAsyncClient* ac = getMigrateAsyncClient(c->db->id);
    if (ac->batched_iterator == NULL) {
        return 0;
    }
    if (!block) {
        return 1;
    }
    serverAssert(c->migrate_async_list == NULL);

    list* ll = ac->blocked_clients;

    // Block current client.
    c->migrate_async_list = ll;
    listAddNodeTail(ll, c);

    blockClient(c, BLOCKED_MIGRATE_ASYNC);
    return 1;
}

static void cleanupRestoreAsyncKeys(redisDb* db, mstime_t now) {
    // Try to remove all expired keys from restore_async_keys.
    // Notes: We don't need to touch the database, since the expired objects
    // will be automatically removed by activeExpireCycle() in databaseCron().
    if (dictSize(db->restore_async_keys) != 0) {
        dictIterator* di = dictGetSafeIterator(db->restore_async_keys);
        dictEntry* entry;
        while ((entry = dictNext(di)) != NULL) {
            mstime_t expire = dictGetSignedIntegerVal(entry);
            if (now != 0 && now < expire) {
                continue;
            }
            dictDelete(db->restore_async_keys, dictGetKey(entry));
        }
        dictReleaseIterator(di);
    }
    // Try to rehash the restore_async_keys.
    if (dictIsRehashing(db->restore_async_keys)) {
        dictRehashMilliseconds(db->restore_async_keys, 1);
    } else if (htNeedsResize(db->restore_async_keys)) {
        dictResize(db->restore_async_keys);
    }
}

static mstime_t lookupRestoreAsyncKeys(redisDb* db, robj* key, mstime_t now) {
    dictEntry* entry = dictFind(db->restore_async_keys, key);
    if (entry != NULL) {
        mstime_t expire = dictGetSignedIntegerVal(entry);
        if (now <= expire) {
            return expire;
        }
        dictDelete(db->restore_async_keys, key);
    }
    return 0;
}

// NOTE: Ensure it's only called by serveCron() in server.c.
// Check for timeouts.
void cleanupClientsForMigrateAsync() {
    for (int db = 0; db < server.dbnum; db++) {
        migrateAsyncClient* ac = getMigrateAsyncClient(db);
        if (ac->c == NULL) {
            continue;
        }
        batchedObjectIterator* it = ac->batched_iterator;
        mstime_t delta = mstime() - ac->lastuse;
        if (delta < ((it != NULL) ? ac->timeout : 1000 * 10)) {
            continue;
        }
        migrateAsyncClientCancelErrorFormat(
            db, (it != NULL) ? "interrupted: migration timeout"
                             : "interrupted: idle timeout");
    }
    for (int db = 0; db < server.dbnum; db++) {
        cleanupRestoreAsyncKeys(&server.db[db], mstime());
    }
}

int inConflictWithMigrateAsync(client* c, struct redisCommand* cmd, robj** argv,
                               int argc) {
    migrateAsyncClient* ac = getMigrateAsyncClient(c->db->id);
    if (ac->batched_iterator == NULL &&
        dictSize(c->db->restore_async_keys) == 0) {
        return 0;
    }
    batchedObjectIterator* it = ac->batched_iterator;

    multiState _ms, *ms = &_ms;
    multiCmd mc;
    if (cmd->proc != execCommand) {
        mc.cmd = cmd;
        mc.argv = argv;
        mc.argc = argc;
        ms->commands = &mc;
        ms->count = 1;
    } else if (c->flags & CLIENT_MULTI) {
        ms = &c->mstate;
    } else {
        return 0;
    }

    mstime_t now = mstime();

    for (int i = 0; i < ms->count; i++) {
        robj** margv;
        int margc, numkeys;
        struct redisCommand* mcmd = ms->commands[i].cmd;

        margv = ms->commands[i].argv;
        margc = ms->commands[i].argc;

        int migrating = 0, restoring = 0;
        int* keyindex = getKeysFromCommand(mcmd, margv, margc, &numkeys);
        for (int j = 0; j < numkeys; j++) {
            robj* key = margv[keyindex[j]];
            if (it != NULL && dictFind(it->keys, key) != NULL) {
                migrating = 1;
            }
            if (mcmd->proc == restoreAsyncCommand) {
                continue;
            }
            if (lookupRestoreAsyncKeys(c->db, key, now) != 0) {
                restoring = 1;
            }
        }
        getKeysFreeResult(keyindex);

        if (restoring) {
            return 1;
        }
        if (migrating && !(mcmd->flags & CMD_READONLY)) {
            return 1;
        }
    }
    return 0;
}

// ==================== Command: MIGRATE-ASNYC-DUMP =========================

// MIGRATE-ASYNC-DUMP $timeout $key1 [$key2 ...]
void migrateAsyncDumpCommand(client* c) {
    long long timeout;
    if (getLongLongFromObject(c->argv[1], &timeout) != C_OK ||
        !(timeout >= 0 && timeout <= INT_MAX)) {
        addReplyErrorFormat(c, "invalid value of timeout (%s)",
                            (char*)c->argv[1]->ptr);
        return;
    }
    if (timeout < 1000) {
        timeout = 1000;
    }

    batchedObjectIterator* it = createBatchedObjectIterator(timeout);
    for (int i = 2; i < c->argc; i++) {
        batchedObjectIteratorAddKey(c->db, it, c->argv[i]);
    }

    void* ptr = addDeferredMultiBulkLength(c);
    int total = 0;
    while (batchedObjectIteratorHasNext(it)) {
        total += batchedObjectIteratorNext(c, it);
    }
    setDeferredMultiBulkLength(c, ptr, total);

    freeBatchedObjectIterator(it);
}

// ==================== Command: MIGRATE-ASNYC ==============================

static int migrateAsyncNextInMicroseconds(migrateAsyncClient* ac, int atleast,
                                          long long usecs) {
    batchedObjectIterator* it = ac->batched_iterator;
    long long start = ustime();
    int sending_messages = 0;
    while (batchedObjectIteratorHasNext(it)) {
        if (ac->pending_messages + sending_messages != 0) {
            size_t usage = getClientOutputBufferMemoryUsage(ac->c);
            size_t limit = server.migrate_async_sendbuf_limit;
            if (limit <= usage) {
                break;
            }
        }
        sending_messages += batchedObjectIteratorNext(ac->c, it);
        if (sending_messages >= atleast && usecs <= ustime() - start) {
            break;
        }
    }
    return sending_messages;
}

// MIGRATE-ASYNC $host $port $timeout $key1 [$key2 ...]
void migrateAsyncCommand(client* c) {
    if (migrateAsyncClientStatusOrBlock(c, 0)) {
        addReplyError(c, "the specified DB is being migrated");
        return;
    }
    if (dictSize(c->db->restore_async_keys) != 0) {
        addReplyError(c, "the specified DB is being imported");
        return;
    }

    sds host = c->argv[1]->ptr;

    long long port;
    if (getLongLongFromObject(c->argv[2], &port) != C_OK ||
        !(port >= 1 && port < 65536)) {
        addReplyErrorFormat(c, "invalid value of port (%s)",
                            (char*)c->argv[2]->ptr);
        return;
    }

    long long timeout;
    if (getLongLongFromObject(c->argv[3], &timeout) != C_OK ||
        !(timeout >= 0 && timeout <= INT_MAX)) {
        addReplyErrorFormat(c, "invalid value of timeout (%s)",
                            (char*)c->argv[3]->ptr);
        return;
    }
    if (timeout < 1000) {
        timeout = 1000;
    }

    migrateAsyncClient* ac =
        migrateAsyncClientInit(c->db->id, host, port, timeout);
    if (ac == NULL) {
        addReplyErrorFormat(c, "connect to %s:%d failed", host, (int)port);
        return;
    }
    serverAssert(ac->pending_messages == 0);
    serverAssert(listLength(ac->blocked_clients) == 0 &&
                 ac->batched_iterator == NULL);

    batchedObjectIterator* it = createBatchedObjectIterator(timeout);
    for (int i = 4; i < c->argc; i++) {
        batchedObjectIteratorAddKey(c->db, it, c->argv[i]);
    }
    ac->batched_iterator = it;

    ac->timeout = timeout;
    ac->lastuse = mstime();

    // Send at least 4 messages with at most 500us.
    ac->pending_messages += migrateAsyncNextInMicroseconds(ac, 4, 500);

    // Block current client until migration is completed.
    migrateAsyncClientStatusOrBlock(c, 1);

    if (ac->pending_messages != 0) {
        return;
    }

    // Nothing happens - no key will be migrated.
    // Wake up current client and mark finished (release iterator).
    migrateAsyncClientInterrupt(ac, NULL);

    ac->batched_iterator = NULL;
    freeBatchedObjectIterator(it);
}

// ==================== Command: MIGRATE-ASNYC-{FENCE/CANCEL/STATUS} ========

// MIGRATE-ASYNC-FENCE
void migrateAsyncFenceCommand(client* c) {
    // Block until the previous migration is completed.
    if (migrateAsyncClientStatusOrBlock(c, 1)) {
        return;
    }
    // Nothing is being migrated, just return -1.
    addReplyLongLong(c, -1);
}

// MIGRATE-ASYNC-CANCEL
void migrateAsyncCancelCommand(client* c) {
    int n = 0;
    for (int db = 0; db < server.dbnum; db++) {
        n += migrateAsyncClientCancelErrorFormat(db, "interrupted: canceled");
    }
    addReplyLongLong(c, n);
}

// MIGRATE-ASYNC-STATUS
void migrateAsyncStatusCommand(client* c) {
    migrateAsyncClient* ac = getMigrateAsyncClient(c->db->id);
    if (ac->c == NULL) {
        addReply(c, shared.nullmultibulk);
        return;
    }
    void* ptr = addDeferredMultiBulkLength(c);
    int total = 0;

    total++;
    addReplyBulkCString(c, "host");
    addReplyBulkCString(c, ac->host);

    total++;
    addReplyBulkCString(c, "port");
    addReplyBulkLongLong(c, ac->port);

    total++;
    addReplyBulkCString(c, "authenticated");
    addReplyBulkLongLong(c, ac->authenticated);

    total++;
    addReplyBulkCString(c, "timeout");
    addReplyBulkLongLong(c, ac->timeout);

    total++;
    addReplyBulkCString(c, "lastuse");
    addReplyBulkLongLong(c, ac->lastuse);

    total++;
    addReplyBulkCString(c, "since_lastuse");
    addReplyBulkLongLong(c, mstime() - ac->lastuse);

    total++;
    addReplyBulkCString(c, "pending_messages");
    addReplyBulkLongLong(c, ac->pending_messages);

    total++;
    addReplyBulkCString(c, "sendbuf_usage");
    addReplyBulkLongLong(c, getClientOutputBufferMemoryUsage(ac->c));

    total++;
    addReplyBulkCString(c, "sendbuf_limit");
    addReplyBulkLongLong(c, server.migrate_async_sendbuf_limit);

    total++;
    addReplyBulkCString(c, "blocked_clients");
    addReplyBulkLongLong(c, listLength(ac->blocked_clients));

    total++;
    addReplyBulkCString(c, "batched_iterator");
    batchedObjectIteratorStatus(c, ac->batched_iterator);

    setDeferredMultiBulkLength(c, ptr, total * 2);
}

// ==================== Command: RESTORE-ASYNC-AUTH =========================

// Respond ACK to the source instance with status=0 to deliver a request.
// This response will trigger the source instance to send more requests.
static void migrateAsyncReplyAckString(client* c, const char* msg) {
    do {
        // RESTORE-ASYNC-ACK $errno $message
        addReplyMultiBulkLen(c, 3);
        addReplyBulkCString(c, "RESTORE-ASYNC-ACK");
        addReplyBulkLongLong(c, 0);
        addReplyBulkCString(c, msg);
    } while (0);
}

// Respond ACK to the source instance with status=1 to cancel migration.
// Client will be closed immediately after reply.
static void migrateAsyncReplyAckErrorFormat(client* c, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    sds errmsg = sdscatvprintf(sdsempty(), fmt, ap);
    va_end(ap);

    do {
        // RESTORE-ASYNC-ACK $errno $message
        addReplyMultiBulkLen(c, 3);
        addReplyBulkCString(c, "RESTORE-ASYNC-ACK");
        addReplyBulkLongLong(c, 1);
        addReplyBulkSds(c, errmsg);
    } while (0);

    // Call freeClient() to close connection after reply.
    c->flags |= CLIENT_CLOSE_AFTER_REPLY;
}

extern int time_independent_strcmp(const char* a, const char* b);

// RESTORE-ASYNC-AUTH $passwd
void restoreAsyncAuthCommand(client* c) {
    if (!server.requirepass) {
        migrateAsyncReplyAckErrorFormat(
            c, "Client sent AUTH, but no password is set");
        return;
    }
    if (!time_independent_strcmp(c->argv[1]->ptr, server.requirepass)) {
        c->authenticated = 1;
        migrateAsyncReplyAckString(c, "OK");
    } else {
        c->authenticated = 0;
        migrateAsyncReplyAckErrorFormat(c, "invalid password");
    }
}

// ==================== Command: RESTORE-ASYNC-SELECT =======================

// RESTORE-ASYNC-SELECT $db
void restoreAsyncSelectCommand(client* c) {
    long long db;
    if (getLongLongFromObject(c->argv[1], &db) != C_OK ||
        !(db >= 0 && db <= INT_MAX) || selectDb(c, db) != C_OK) {
        migrateAsyncReplyAckErrorFormat(c, "invalid DB index (%s)",
                                        c->argv[1]->ptr);
    } else {
        migrateAsyncReplyAckString(c, "OK");
    }
}

// ==================== Command: RESTORE-ASYNC ==============================

// RESTORE-ASYNC delete $key
static int restoreAsyncCommandDeleteKey(client* c, robj* key) {
    // Delete the key asynchronously.
    if (dbAsyncDelete(c->db, key)) {
        signalModifiedKey(c->db, key);
        server.dirty++;
    }
    return C_OK;
}

// RESTORE-ASYNC expire $key $ttlms
static int restoreAsyncCommandExpireKey(client* c, robj* key) {
    robj* obj = lookupKeyWrite(c->db, key);
    if (obj == NULL) {
        migrateAsyncReplyAckErrorFormat(
            c, "the specified key doesn't exist (%s)", key->ptr);
        return C_ERR;
    }
    return C_OK;
}

extern int verifyDumpPayload(unsigned char* p, size_t len);

// RESTORE-ASYNC object $key $ttlms $payload
static int restoreAsyncCommandTypeObject(client* c, robj* key) {
    if (lookupKeyWrite(c->db, key) != NULL) {
        migrateAsyncReplyAckErrorFormat(
            c, "the specified key already exists (%s)", key->ptr);
        return C_ERR;
    }

    rio payload;
    void* bytes = c->argv[4]->ptr;
    if (verifyDumpPayload(bytes, sdslen(bytes)) != C_OK) {
        migrateAsyncReplyAckErrorFormat(c, "invalid payload checksum (%s)",
                                        key->ptr);
        return C_ERR;
    }
    rioInitWithBuffer(&payload, bytes);

    int type = rdbLoadObjectType(&payload);
    if (type == -1) {
        migrateAsyncReplyAckErrorFormat(c, "invalid payload type (%s)",
                                        key->ptr);
        return C_ERR;
    }

    robj* obj = rdbLoadObject(type, &payload);
    if (obj == NULL) {
        migrateAsyncReplyAckErrorFormat(c, "invalid payload body (%s)",
                                        key->ptr);
        return C_ERR;
    }

    dbAdd(c->db, key, obj);
    return C_OK;
}

// RESTORE-ASYNC string $key $ttlms $payload
static int restoreAsyncCommandTypeString(client* c, robj* key) {
    if (lookupKeyWrite(c->db, key) != NULL) {
        migrateAsyncReplyAckErrorFormat(
            c, "the specified key already exists (%s)", key->ptr);
        return C_ERR;
    }

    robj* obj = c->argv[4] = tryObjectEncoding(c->argv[4]);

    incrRefCount(obj);
    dbAdd(c->db, key, obj);
    return C_OK;
}

// RESTORE-ASYNC list $key $ttlms $maxsize [$elem1 ...]
static int restoreAsyncCommandTypeList(client* c, robj* key, int argc,
                                       robj** argv) {
    robj* obj = lookupKeyWrite(c->db, key);
    if (obj != NULL) {
        if (obj->type != OBJ_LIST || obj->encoding != OBJ_ENCODING_QUICKLIST) {
            migrateAsyncReplyAckErrorFormat(
                c, "wrong object type (%d/%d,expect=%d/%d)", obj->type,
                obj->encoding, OBJ_LIST, OBJ_ENCODING_QUICKLIST);
            return C_ERR;
        }
    } else {
        obj = createQuicklistObject();
        quicklistSetOptions(obj->ptr, server.list_max_ziplist_size,
                            server.list_compress_depth);
        dbAdd(c->db, key, obj);
    }

    // Call RPUSH to rebuild this list object.
    for (int i = 0; i < argc; i++) {
        listTypePush(obj, argv[i], LIST_TAIL);
    }
    return C_OK;
}

// RESTORE-ASYNC hash $key $ttlms $maxsize [$hkey1 $hval1 ...]
static int restoreAsyncCommandTypeHash(client* c, robj* key, int argc,
                                       robj** argv, long long size) {
    robj* obj = lookupKeyWrite(c->db, key);
    if (obj != NULL) {
        if (obj->type != OBJ_HASH || obj->encoding != OBJ_ENCODING_HT) {
            migrateAsyncReplyAckErrorFormat(
                c, "wrong object type (%d/%d,expect=%d/%d)", obj->type,
                obj->encoding, OBJ_HASH, OBJ_ENCODING_HT);
            return C_ERR;
        }
    } else {
        obj = createHashObject();
        if (obj->encoding != OBJ_ENCODING_HT) {
            hashTypeConvert(obj, OBJ_ENCODING_HT);
        }
        dbAdd(c->db, key, obj);
    }

    // Resize the hash table for better performance.
    if (size != 0) {
        dict* ht = obj->ptr;
        dictExpand(ht, size);
    }

    // Call HMSET to rebuild this hash object.
    for (int i = 0; i < argc; i += 2) {
        hashTypeSet(obj, argv[i]->ptr, argv[i + 1]->ptr, HASH_SET_COPY);
    }
    return C_OK;
}

// RESTORE-ASYNC set $key $ttlms $maxsize [$elem1 ...]
static int restoreAsyncCommandTypeSet(client* c, robj* key, int argc,
                                      robj** argv, long long size) {
    robj* obj = lookupKeyWrite(c->db, key);
    if (obj != NULL) {
        if (obj->type != OBJ_SET || obj->encoding != OBJ_ENCODING_HT) {
            migrateAsyncReplyAckErrorFormat(
                c, "wrong object type (%d/%d,expect=%d/%d)", obj->type,
                obj->encoding, OBJ_SET, OBJ_ENCODING_HT);
            return C_ERR;
        }
    } else {
        obj = createSetObject();
        if (obj->encoding != OBJ_ENCODING_HT) {
            setTypeConvert(obj, OBJ_ENCODING_HT);
        }
        dbAdd(c->db, key, obj);
    }

    // Resize the hash table for better performance.
    if (size != 0) {
        dict* ht = obj->ptr;
        dictExpand(ht, size);
    }

    // Call SADD to rebuild this set object.
    for (int i = 0; i < argc; i++) {
        setTypeAdd(obj, argv[i]->ptr);
    }
    return C_OK;
}

// RESTORE-ASYNC zset $key $ttlms $maxsize [$elem1 $score1 ...]
static int restoreAsyncCommandTypeZSet(client* c, robj* key, int argc,
                                       robj** argv, long long size) {
    double* scores = zmalloc(sizeof(double) * (argc / 2));
    for (int i = 1, j = 0; i < argc; i += 2, j++) {
        double v;
        if (longToDoubleFromObject(argv[i], &v) != C_OK) {
            migrateAsyncReplyAckErrorFormat(
                c, "invalid value of score[%d] (%s)", j, argv[i]->ptr);
            zfree(scores);
            return C_ERR;
        }
        scores[j] = v;
    }

    robj* obj = lookupKeyWrite(c->db, key);
    if (obj != NULL) {
        if (obj->type != OBJ_ZSET || obj->encoding != OBJ_ENCODING_SKIPLIST) {
            migrateAsyncReplyAckErrorFormat(
                c, "wrong object type (%d/%d,expect=%d/%d)", obj->type,
                obj->encoding, OBJ_ZSET, OBJ_ENCODING_SKIPLIST);
            zfree(scores);
            return C_ERR;
        }
    } else {
        obj = createZsetObject();
        if (obj->encoding != OBJ_ENCODING_SKIPLIST) {
            zsetConvert(obj, OBJ_ENCODING_SKIPLIST);
        }
        dbAdd(c->db, key, obj);
    }

    // Resize the hash table for better performance.
    if (size != 0) {
        zset* zs = obj->ptr;
        dict* ht = zs->dict;
        dictExpand(ht, size);
    }

    // Call ZADD to rebuild this zset object.
    for (int i = 0, j = 0; i < argc; i += 2, j++) {
        int flags = ZADD_NONE;
        zsetAdd(obj, scores[j], argv[i]->ptr, &flags, NULL);
    }
    zfree(scores);
    return C_OK;
}

static void updateRestoreAsyncKeys(redisDb* db, robj* key, mstime_t expire) {
    dictEntry* entry = dictFind(db->restore_async_keys, key);
    if (entry == NULL) {
        incrRefCount(key);
        entry = dictAddRaw(db->restore_async_keys, key, NULL);
    }
    dictSetSignedIntegerVal(entry, expire);
}

static void deleteRestoreAsyncKeys(redisDb* db, robj* key) {
    dictDelete(db->restore_async_keys, key);
}

// RESTORE-ASYNC delete $key
//               expire $key $ttlms
//               object $key $ttlms $payload
//               string $key $ttlms $payload
//               list   $key $ttlms $maxsize [$elem1 ...]
//               hash   $key $ttlms $maxsize [$hkey1 $hval1 ...]
//               dict   $key $ttlms $maxsize [$elem1 ...]
//               zset   $key $ttlms $maxsize [$elem1 $score1 ...]
void restoreAsyncCommand(client* c) {
    // Check if there's a restore/migrate conflict.
    if (migrateAsyncClientStatusOrBlock(c, 0)) {
        migrateAsyncReplyAckErrorFormat(c,
                                        "the specified DB is being migrated");
        return;
    }

    const char* cmd = "(nil)";
    if (c->argc <= 1) {
        goto bad_arguments_number;
    }
    cmd = c->argv[1]->ptr;

    if (c->argc <= 2) {
        goto bad_arguments_number;
    }
    robj* key = c->argv[2];

    long long ttlms = 0, restoring_partial = 0;

    // RESTORE-ASYNC delete $key
    if (!strcasecmp(cmd, "delete")) {
        if (c->argc != 3) {
            goto bad_arguments_number;
        }
        if (restoreAsyncCommandDeleteKey(c, key) == C_OK) {
            goto success_common_reply;
        }
        return;
    }

    if (c->argc <= 3) {
        goto bad_arguments_number;
    }
    if (getLongLongFromObject(c->argv[3], &ttlms) != C_OK || ttlms < 0) {
        migrateAsyncReplyAckErrorFormat(c, "invalid value of ttlms (%s)",
                                        c->argv[3]->ptr);
        return;
    }

    // RESTORE-ASYNC expire $key $ttlms
    if (!strcasecmp(cmd, "expire")) {
        if (c->argc != 4) {
            goto bad_arguments_number;
        }
        if (restoreAsyncCommandExpireKey(c, key) == C_OK) {
            goto success_common_ttlms;
        }
        return;
    }

    // RESTORE-ASYNC object $key $ttlms $payload
    if (!strcasecmp(cmd, "object")) {
        if (c->argc != 5) {
            goto bad_arguments_number;
        }
        if (restoreAsyncCommandTypeObject(c, key) == C_OK) {
            goto success_common_ttlms;
        }
        return;
    }

    // RESTORE-ASYNC string $key $ttlms $payload
    if (!strcasecmp(cmd, "string")) {
        if (c->argc != 5) {
            goto bad_arguments_number;
        }
        if (restoreAsyncCommandTypeString(c, key) == C_OK) {
            goto success_common_ttlms;
        }
        return;
    }

    if (c->argc <= 4) {
        goto bad_arguments_number;
    }
    long long maxsize;
    if (getLongLongFromObject(c->argv[4], &maxsize) != C_OK || maxsize < 0) {
        migrateAsyncReplyAckErrorFormat(c, "invalid value of maxsize (%s)",
                                        c->argv[4]->ptr);
        return;
    }
    int argc = c->argc - 5;
    robj** argv = &c->argv[5];

    // Make sure the restore_async_keys can be updated with the temporary ttlms.
    restoring_partial = 1;

    // RESTORE-ASYNC list $key $ttlms $maxsize [$elem1 ...]
    if (!strcasecmp(cmd, "list")) {
        if (argc <= 0) {
            goto bad_arguments_number;
        }
        if (restoreAsyncCommandTypeList(c, key, argc, argv) == C_OK) {
            goto success_common_ttlms;
        }
        return;
    }

    // RESTORE-ASYNC hash $key $ttlms $maxsize [$hkey1 $hval1 ...]
    if (!strcasecmp(cmd, "hash")) {
        if (argc <= 0 || argc % 2 != 0) {
            goto bad_arguments_number;
        }
        if (restoreAsyncCommandTypeHash(c, key, argc, argv, maxsize) == C_OK) {
            goto success_common_ttlms;
        }
        return;
    }

    // RESTORE-ASYNC set $key $ttlms $maxsize [$elem1 ...]
    if (!strcasecmp(cmd, "set")) {
        if (argc <= 0) {
            goto bad_arguments_number;
        }
        if (restoreAsyncCommandTypeSet(c, key, argc, argv, maxsize) == C_OK) {
            goto success_common_ttlms;
        }
        return;
    }

    // RESTORE-ASYNC zset $key $ttlms $maxsize [$elem1 $score1 ...]
    if (!strcasecmp(cmd, "zset")) {
        if (argc <= 0 || argc % 2 != 0) {
            goto bad_arguments_number;
        }
        if (restoreAsyncCommandTypeZSet(c, key, argc, argv, maxsize) == C_OK) {
            goto success_common_ttlms;
        }
        return;
    }

    migrateAsyncReplyAckErrorFormat(c, "unknown command (cmd=%s,argc=%d)", cmd,
                                    c->argc);
    return;

success_common_ttlms:
    if (ttlms != 0) {
        setExpire(c, c->db, key, mstime() + ttlms);
    } else {
        removeExpire(c->db, key);
    }
    signalModifiedKey(c->db, key);
    server.dirty++;

success_common_reply:
    if (ttlms != 0 && restoring_partial) {
        updateRestoreAsyncKeys(c->db, key, mstime() + ttlms);
    } else {
        deleteRestoreAsyncKeys(c->db, key);
    }
    migrateAsyncReplyAckString(c, "OK");
    return;

bad_arguments_number:
    migrateAsyncReplyAckErrorFormat(c, "invalid arguments (cmd=%s,argc=%d)",
                                    cmd, c->argc);
    return;
}

// ==================== Command: RESTORE-ASYNC-ACK===========================

static int restoreAsyncAckCommandHandle(client* c) {
    // Only the migration client can call this function.
    migrateAsyncClient* ac = getMigrateAsyncClient(c->db->id);
    if (ac->c != c) {
        addReplyErrorFormat(c, "invalid client, permission denied");
        return C_ERR;
    }

    long long errcode;
    if (getLongLongFromObject(c->argv[1], &errcode) != C_OK) {
        addReplyErrorFormat(c, "invalid value of errcode (%s)",
                            (char*)c->argv[1]->ptr);
        return C_ERR;
    }

    if (errcode != 0) {
        serverLog(LL_WARNING, "migrate_async[%d]: error[%d] (%s)", c->fd,
                  (int)errcode, (char*)c->argv[2]->ptr);
        return C_ERR;
    }

    batchedObjectIterator* it = ac->batched_iterator;
    if (it == NULL) {
        serverLog(LL_WARNING, "migrate_async[%d]: nil batched iterator", c->fd);
        addReplyError(c, "invalid iterator (nil)");
        return C_ERR;
    }
    if (ac->pending_messages == 0) {
        serverLog(LL_WARNING, "migrate_async[%d]: not sending messages", c->fd);
        addReplyError(c, "invalid iterator (pending_messages=0)");
        return C_ERR;
    }
    it->delivered_messages++;

    // Send at least 2 messages with at most 10us (grow exponentially).
    ac->lastuse = mstime();
    ac->pending_messages -= 1;
    ac->pending_messages += migrateAsyncNextInMicroseconds(ac, 2, 10);

    if (ac->pending_messages != 0) {
        return C_OK;
    }
    migrateAsyncClientInterrupt(ac, NULL);

    // Remove all migrated keys from database asynchronously.
    if (listLength(it->finished_keys) != 0) {
        list* ll = it->finished_keys;

        // Propagate a DEL command to AOF and slaves.
        for (int i = 0; i < c->argc; i++) {
            decrRefCount(c->argv[i]);
        }
        zfree(c->argv);

        c->argc = 1 + listLength(ll);
        c->argv = zmalloc(sizeof(c->argv[0]) * c->argc);

        for (int i = 1; i < c->argc; i++) {
            listNode* head = listFirst(ll);
            robj* key = listNodeValue(head);

            // Delete the key asynchronously.
            if (dbAsyncDelete(c->db, key)) {
                signalModifiedKey(c->db, key);
                server.dirty++;
            }
            c->argv[i] = key;
            incrRefCount(key);

            listDelNode(ll, head);
        }
        c->argv[0] = createStringObject("DEL", 3);
    }

    ac->batched_iterator = NULL;
    freeBatchedObjectIterator(it);
    return C_OK;
}

// RESTORE-ASYNC-ACK $errno $message
void restoreAsyncAckCommand(client* c) {
    if (restoreAsyncAckCommandHandle(c) != C_OK) {
        c->flags |= CLIENT_CLOSE_AFTER_REPLY;
    }
}
