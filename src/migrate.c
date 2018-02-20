#include "server.h"

/* ---------------- TODO ---------------------------------------------------- */

void migrateBackgroundThread(void) {}
void migrateCommand(client* c) { UNUSED(c); }
void migrateAsyncCommand(client* c) { UNUSED(c); }
void restoreCommand(client* c) { UNUSED(c); }
void restoreAsyncCommand(client* c) { UNUSED(c); }
void unblockClientFromMigrate(client* c) { UNUSED(c); }
void unblockClientFromRestore(client* c) { UNUSED(c); }
void freeMigrateCommandArgsFromFreeClient(client* c) { UNUSED(c); }
void freeRestoreCommandArgsFromFreeClient(client* c) { UNUSED(c); }
void migrateCloseTimedoutSockets(void) {}
void restoreCloseTimedoutCommands(void) {}
