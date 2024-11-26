#ifndef _LIB_GS_BUS_INCLUDED
#define _LIB_GS_BUS_INCLUDED

#include <stdint.h>


/*
 * Structure to manage the portal connection
 *
 *      connection: holds the DBusConnection* type related to libdbus.
 *      session_id: holds the object path of the org.freedesktop.portal.GlobalShortcuts portal's session.
 *      _queue: holds a pointer to the internal message queue, NOT to be used directly.
 *
 */
struct gs_Session {
	void *connection;
	const char *session_id;
	void *_queue;
};



/*
 * Structure to represent a GlobalShortcut
 *
 *      name: holds the identifier to assign for / retrieve from a shortcut.
 *      description: holds the shortcut's description.
 *      trigger: holds the trigger combination for the shortcut.
 *
 *      NOTE: sent triggers follow the shortcuts XDG specification,
 *            retrieved triggers are assigned from the service and can differ widely.
 *
 */
struct gs_Shortcut {
	char *name;
	char *description;
	char *trigger;
};



/*
 * Possible return values
 *
 *      Functions that execute with no errros will return 0,
 *      otherwise a value of the following ones.
 *
 */
enum gs_ErrorCode {
	GS_CONNECTION_ERROR = 1, // error creating the connection, D-Bus error retrieved
	GS_BAD_CONNECTION,       // error creating the connection, no error retrieved
	GS_MSG_CREATION_ERROR,   // error creating the message, no error retrieved
	GS_REPLY_ERROR,          // error in the retrieved reply, D-Bus error retrieved
	GS_BAD_REPLY,            // error in the retrieved reply, no error retrieved
	GS_BAD_SIGNAL            // error in the retrieved Response (got non-zero value), no error retrieved
};



/*
 * The following functions assume all pointer arguments not to be NULL,
 * with the only exception being the "timestamp" and "error" arguments.
 * 
 * If not NULL, "error" can point to a valid DBusError variable, which can then be used.
 *
 */



/*
 * Empties the gs_Session's internal queue
 *
 */
void gs_ClearQueue(struct gs_Session *session);



/*
 * Initializes a new gs_Session
 *
 *      app_id will be used to determine the org.freedesktop.portal.Session path,
 *      which keeps GlobalShortcuts across different sessions.
 *
 */
int gs_CreateSession(struct gs_Session *session, const char *app_id, void *error);



/*
 * Closes the session and frees allocated pointers
 *
 */
void gs_CloseSession(struct gs_Session *session);



/*
 * Calls org.freedesktop.portal.GlobalShortcuts.BindShortcuts
 *
 *      shortcut_list: an array of gs_Shortcut.
 *      num: the length of said array.
 *
 */
int gs_BindShortcuts(struct gs_Session *session, struct gs_Shortcut *shortcut_list, int num, void *error);



/*
 * Calls org.freedesktop.portal.GlobalShortcuts.ListShortcuts
 *
 *      shortcut_list: the passed pointer will hold the resulting allocated array.
 *      num: will hold the length of said array.
 *
 */
int gs_ListShortcuts(struct gs_Session *session, struct gs_Shortcut **shortcut_list, int *num, void *error);



/*
 * Procecess the first org.freedesktop.portal.GlobalShortcuts::Activated signal, if any
 *
 *      shortcut_id: the passed pointer will hold the resulting shortcut's name.
 *      timestamp: optional, will hold the timestamp passed from the service, in milliseconds.
 *
 */
int gs_GetActivated(struct gs_Session *session, const char **shortcut_id, uint64_t *timestamp, void *error);



/*
 * Procecess the first org.freedesktop.portal.GlobalShortcuts::Deactivated signal, if any
 *
 *      shortcut_id: the passed pointer will hold the resulting shortcut's name.
 *      timestamp: optional, will hold the timestamp passed from the service, in milliseconds.
 *
 */
int gs_GetDeactivated(struct gs_Session *session, const char **shortcut_id, uint64_t *timestamp, void *error);



/*
 * Procecess the first org.freedesktop.portal.GlobalShortcuts::ShortcutsChanged signal, if any
 *
 *      shortcut_list: the passed pointer will hold the resulting allocated array.
 *      num: will hold the length of said array.
 *
 */
int gs_GetShortcutsChanged(struct gs_Session *session, struct gs_Shortcut **shortcut_list, int *num, void *error);

#endif // _LIB_GS_BUS_INCLUDED
