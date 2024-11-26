#ifndef _LIB_GS_BUS_INCLUDED
#define _LIB_GS_BUS_INCLUDED

struct gs_Session {
	void *connection;
	const char *session_id;
	void *_queue;
};

struct gs_Shortcut {
	char *name;
	char *description;
	char *trigger;
};

enum gs_ErrorCode {
	CONNECTION_ERROR = 1,
	BAD_CONNECTION,
	MSG_CREATION_ERROR,
	REPLY_ERROR,
	BAD_REPLY,
	BAD_SIGNAL
};

void gs_ClearQueue(struct gs_Session *session);

int gs_CreateSession(struct gs_Session *session, const char *app_id, void *error);

void gs_CloseSession(struct gs_Session *session);

int gs_BindShortcuts(struct gs_Session *session, struct gs_Shortcut *shortcut_list, int num, void *error);

int gs_ListShortcuts(struct gs_Session *session, struct gs_Shortcut **shortcut_list, int *num, void *error);

int gs_GetActivated(struct gs_Session *session, const char **shortcut_id, uint64_t *timestamp, void *error);

int gs_GetDeactivated(struct gs_Session *session, const char **shortcut_id, uint64_t *timestamp, void *error);

int gs_GetShortcutsChanged(struct gs_Session *session, struct gs_Shortcut **shortcut_list, int *num, void *error);

#endif
