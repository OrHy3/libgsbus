#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>
#include <dbus/dbus.h>

#include "gsbus.h"

#define PORTAL_TARGET "org.freedesktop.portal.Desktop"
#define PORTAL_OBJECT "/org/freedesktop/portal/desktop"
#define PORTAL_INTERFACE "org.freedesktop.portal.GlobalShortcuts"

struct __gs_Msg {
	DBusMessage *message;
	struct __gs_Msg *prev;
	struct __gs_Msg *next;
};

struct __gs_Queue {
	struct __gs_Msg *top;
	struct __gs_Msg *bottom;
	int access_count;
	void *unique_addr;
	int unique_rand;
};

void __gs_claim_queue(struct gs_Session *session) {

	int local;
	getrandom(&local, sizeof(local), GRND_NONBLOCK);

	struct __gs_Queue *queue = (struct __gs_Queue*)session->_queue;

	while (1) {

		while (queue->access_count > 0)
			sleep(1);

		queue->access_count++;
		queue->unique_addr = &local;
		queue->unique_rand = local;

		if (queue->access_count > 1 && (queue->unique_addr != &local || queue->unique_rand != local))
			queue->access_count--;
		else
			break;

	}

}

void __gs_release_queue(struct gs_Session *session) {
	struct __gs_Queue *queue = (struct __gs_Queue*)session->_queue;
	queue->unique_addr = NULL;
	queue->unique_rand = 0;
	queue->access_count--;
}

void __gs_queue_push_msg(struct gs_Session *session, DBusMessage *message) {

	struct __gs_Queue *queue = (struct __gs_Queue*)session->_queue;
	struct __gs_Msg *new_element = malloc(sizeof(struct __gs_Msg));

	new_element->message = message;
	new_element->next = NULL;

	if (queue->top == NULL) {
		new_element->prev = NULL;
		queue->top = new_element;
	} else {
		new_element->prev = queue->bottom;
		new_element->prev->next = new_element;
	}

	queue->bottom = new_element;

}

void __gs_queue_pop_msg(struct gs_Session *session, struct __gs_Msg *element) {

	struct __gs_Queue *queue = (struct __gs_Queue*)session->_queue;

	if (element->prev)
		element->prev->next = element->next;
	if (element->next)
		element->next->prev = element->prev;
	if (queue->top == element)
		queue->top = element->next;
	if (queue->bottom == element)
		queue->bottom = element->prev;

	free(element);

}

int __gs_is_signal_relevant(struct gs_Session *session, DBusMessage *message) {

		if (!dbus_message_is_signal(message, "org.freedesktop.portal.GlobalShortcuts", "Activated") && !dbus_message_is_signal(message, "org.freedesktop.portal.GlobalShortcuts", "Deactivated") && !dbus_message_is_signal(message, "org.freedesktop.portal.GlobalShortcuts", "ShortcutsChanged"))
			return 0;

		DBusMessageIter args;
		DBusMessage *temp = dbus_message_copy(message);
		dbus_message_iter_init(temp, &args);
		const char *result;
		dbus_message_iter_get_basic(&args, &result);

		int ret = (strcmp(result, session->session_id) == 0);
		dbus_message_unref(temp);
		return ret;

}

void gs_ClearQueue(struct gs_Session *session) {
	struct __gs_Queue *queue = (struct __gs_Queue*)session->_queue;
	while (queue->top != NULL)
		__gs_queue_pop_msg(session, queue->top);
}

int gs_CreateSession(struct gs_Session *session, const char *app_id, void *error) {

	if (error != NULL)
		dbus_error_init(error);

	session->connection = dbus_bus_get_private(DBUS_BUS_SESSION, error);
	if (error != NULL && dbus_error_is_set(error)) {
		dbus_connection_close((DBusConnection*)session->connection);
		session->connection = NULL;
		return GS_CONNECTION_ERROR;
	}

	if ((DBusConnection*)session->connection == NULL)
		return GS_BAD_CONNECTION;

	dbus_connection_set_exit_on_disconnect((DBusConnection*)session->connection, 0);

	DBusMessage *message;
	message = dbus_message_new_method_call(
		PORTAL_TARGET,
		PORTAL_OBJECT,
		PORTAL_INTERFACE,
		"CreateSession"
	);
	if (message == NULL) {
		dbus_connection_close((DBusConnection*)session->connection);
		session->connection = NULL;
		return GS_MSG_CREATION_ERROR;
	}

	unsigned random_id;
	getrandom(&random_id, sizeof(random_id), GRND_NONBLOCK);

	char token_string[256];
	snprintf(token_string, sizeof(token_string), "gsbus_%d\0", random_id % 10000);
	const char *token_string_ptr = token_string;

	DBusMessageIter args;
	DBusMessageIter array_iter;
	DBusMessageIter dict_iter;
	DBusMessageIter variant_iter;

	dbus_message_iter_init_append(message, &args);

	dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sv}", &array_iter);

	dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &dict_iter);

	char *dict_keys[2] = {
		"handle_token",
		"session_handle_token"
	};

	dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &dict_keys[0]);

	dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_VARIANT, "s", &variant_iter);

	dbus_message_iter_append_basic(&variant_iter, DBUS_TYPE_STRING, &token_string_ptr);

	dbus_message_iter_close_container(&dict_iter, &variant_iter);
	dbus_message_iter_close_container(&array_iter, &dict_iter);

	dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &dict_iter);

	dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &dict_keys[1]);

	dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_VARIANT, "s", &variant_iter);

	if (app_id == NULL)
		dbus_message_iter_append_basic(&variant_iter, DBUS_TYPE_STRING, &token_string_ptr);
	else
		dbus_message_iter_append_basic(&variant_iter, DBUS_TYPE_STRING, &app_id);

	dbus_message_iter_close_container(&dict_iter, &variant_iter);
	dbus_message_iter_close_container(&array_iter, &dict_iter);
	dbus_message_iter_close_container(&args, &array_iter);

	DBusMessage *reply;
	reply = dbus_connection_send_with_reply_and_block((DBusConnection*)session->connection, message, DBUS_TIMEOUT_USE_DEFAULT, error);
	dbus_message_unref(message);
	if (error != NULL && dbus_error_is_set(error)) {
		if (reply)
			dbus_message_unref(reply);
		dbus_connection_unref((DBusConnection*)session->connection);
		session->connection = NULL;
		return GS_REPLY_ERROR;
	}

	if (reply == NULL) {
		dbus_connection_unref((DBusConnection*)session->connection);
		session->connection = NULL;
		return GS_BAD_REPLY;
	}

	dbus_message_iter_init(reply, &args);

	const char *request_id;
	dbus_message_iter_get_basic(&args, &request_id);

	dbus_message_unref(reply);

	do {

		dbus_connection_read_write((DBusConnection*)session->connection, 1);
		reply = dbus_connection_pop_message((DBusConnection*)session->connection);

		if (reply != NULL && dbus_message_is_signal(reply, "org.freedesktop.portal.Request", "Response") && strcmp(dbus_message_get_path(reply), request_id) == 0)
			break;

	} while (1);

	dbus_message_iter_init(reply, &args);

	int status;
	dbus_message_iter_get_basic(&args, &status);
	if (status != 0) {
		dbus_message_unref(reply);
		dbus_connection_close((DBusConnection*)session->connection);
		session->connection = NULL;
		return GS_BAD_SIGNAL;
	}

	dbus_message_iter_next(&args);

	dbus_message_iter_recurse(&args, &array_iter);
	dbus_message_iter_recurse(&array_iter, &dict_iter);

	dbus_message_iter_next(&dict_iter);

	dbus_message_iter_recurse(&dict_iter, &variant_iter);

	const char *session_id;
	dbus_message_iter_get_basic(&variant_iter, &session_id);
	session->session_id = malloc(strlen(session_id) + 1);
	strcpy(session->session_id, session_id);

	dbus_message_unref(reply);

	session->_queue = malloc(sizeof(struct __gs_Queue));
	((struct __gs_Queue*)session->_queue)->top = NULL;
	((struct __gs_Queue*)session->_queue)->bottom = NULL;
	((struct __gs_Queue*)session->_queue)->access_count = 0;
	((struct __gs_Queue*)session->_queue)->unique_addr = NULL;
	((struct __gs_Queue*)session->_queue)->unique_rand = 0;
	
	return 0;

}

void gs_CloseSession(struct gs_Session *session) {

	if (session == NULL)
		return;

	if ((DBusConnection*)session->connection && dbus_connection_get_is_connected(session->connection)) {

		if ((DBusConnection*)session->connection) {

			DBusMessage *message = dbus_message_new_method_call(
				PORTAL_TARGET,
				session->session_id,
				"org.freedesktop.portal.Session",
				"Close"
			);

			dbus_connection_send((DBusConnection*)session->connection, message, NULL);

		}

		dbus_connection_close((DBusConnection*)session->connection);
		dbus_connection_unref((DBusConnection*)session->connection);

	}

	if (session->session_id != NULL) {
		free(session->session_id);
		session->session_id = NULL;
	}

	gs_ClearQueue(session);
	free(session->_queue);

}

int gs_BindShortcuts(struct gs_Session *session, struct gs_Shortcut *shortcut_list, int num, void *error) {

	if (error != NULL)
		dbus_error_init(error);

	DBusMessage *message = dbus_message_new_method_call(
		PORTAL_TARGET,
		PORTAL_OBJECT,
		PORTAL_INTERFACE,
		"BindShortcuts"
	);
	if (message == NULL)
		return GS_MSG_CREATION_ERROR;

	DBusMessageIter args;
	DBusMessageIter array_iter;
	DBusMessageIter struct_iter;
	DBusMessageIter subarray_iter;
	DBusMessageIter dict_iter;
	DBusMessageIter variant_iter;

	dbus_message_iter_init_append(message, &args);

	dbus_message_iter_append_basic(&args, DBUS_TYPE_OBJECT_PATH, &session->session_id);

	dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "(sa{sv})", &array_iter);

	for (int i = 0; i < num; i++) {

		dbus_message_iter_open_container(&array_iter, DBUS_TYPE_STRUCT, NULL, &struct_iter);
	
		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &shortcut_list[i].name);
	
		dbus_message_iter_open_container(&struct_iter, DBUS_TYPE_ARRAY, "{sv}", &subarray_iter);
		dbus_message_iter_open_container(&subarray_iter, DBUS_TYPE_DICT_ENTRY, NULL, &dict_iter);
	
		const char *description_key = "description";
		dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &description_key);
	
		dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_VARIANT, "s", &variant_iter);
	
		dbus_message_iter_append_basic(&variant_iter, DBUS_TYPE_STRING, &shortcut_list[i].description);
	
		dbus_message_iter_close_container(&dict_iter, &variant_iter);
		dbus_message_iter_close_container(&subarray_iter, &dict_iter);

		if (shortcut_list[i].trigger != NULL) {
		
			dbus_message_iter_open_container(&subarray_iter, DBUS_TYPE_DICT_ENTRY, NULL, &dict_iter);

			const char *trigger_key = "preferred_trigger";
			dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &trigger_key);

			dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_VARIANT, "s", &variant_iter);

			dbus_message_iter_append_basic(&variant_iter, DBUS_TYPE_STRING, &shortcut_list[i].trigger);
	
			dbus_message_iter_close_container(&dict_iter, &variant_iter);
			dbus_message_iter_close_container(&subarray_iter, &dict_iter);

		}

		dbus_message_iter_close_container(&struct_iter, &subarray_iter);
		dbus_message_iter_close_container(&array_iter, &struct_iter);

	}

	dbus_message_iter_close_container(&args, &array_iter);

	const char *parent_window = "";
	dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &parent_window);

	dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sv}", &array_iter);

	dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &dict_iter);

	unsigned random_id;
	getrandom(&random_id, sizeof(random_id), GRND_NONBLOCK);

	const char *dict_key = "handle_token";
	char token_string[256];
	snprintf(token_string, sizeof(token_string), "gsbus_%d\0", random_id % 10000);
	const char *token_string_ptr = token_string;

	dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &dict_key);

	dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_VARIANT, "s", &variant_iter);

	dbus_message_iter_append_basic(&variant_iter, DBUS_TYPE_STRING, &token_string_ptr);

	dbus_message_iter_close_container(&dict_iter, &variant_iter);
	dbus_message_iter_close_container(&array_iter, &dict_iter);
	dbus_message_iter_close_container(&args, &array_iter);

	DBusMessage *reply = dbus_connection_send_with_reply_and_block((DBusConnection*)session->connection, message, DBUS_TIMEOUT_USE_DEFAULT, error);
	dbus_message_unref(message);
	if (error != NULL && dbus_error_is_set(error)) {
		if (reply)
			dbus_message_unref(reply);
		return GS_REPLY_ERROR;
	}

	if (reply == NULL)
		return GS_BAD_REPLY;

	dbus_message_unref(reply);

	return 0;

}

int gs_ListShortcuts(struct gs_Session *session, struct gs_Shortcut **shortcut_list, int *num, void *error) {

	if (error != NULL)
		dbus_error_init(error);

	DBusMessage *message = dbus_message_new_method_call(
		PORTAL_TARGET,
		PORTAL_OBJECT,
		PORTAL_INTERFACE,
		"ListShortcuts"
	);
	if (message == NULL)
		return GS_MSG_CREATION_ERROR;

	DBusMessageIter args;
	DBusMessageIter array_iter;
	DBusMessageIter struct_iter;
	DBusMessageIter subarray_iter;
	DBusMessageIter dict_iter;
	DBusMessageIter variant_iter;

	dbus_message_iter_init_append(message, &args);

	dbus_message_iter_append_basic(&args, DBUS_TYPE_OBJECT_PATH, &session->session_id);

	dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sv}", &array_iter);
	dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &dict_iter);

	const char *options_key = "handle_token";
	dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &options_key);

	dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_VARIANT, "s", &variant_iter);

	unsigned random_id;
	getrandom(&random_id, sizeof(random_id), GRND_NONBLOCK);
	char token_string[256];
	snprintf(token_string, sizeof(token_string), "gsbus_%d\0", random_id % 10000);
	const char *token_string_ptr = token_string;

	dbus_message_iter_append_basic(&variant_iter, DBUS_TYPE_STRING, &token_string_ptr);

	dbus_message_iter_close_container(&dict_iter, &variant_iter);
	dbus_message_iter_close_container(&array_iter, &dict_iter);
	dbus_message_iter_close_container(&args, &array_iter);

	DBusMessage *reply = dbus_connection_send_with_reply_and_block((DBusConnection*)session->connection, message, DBUS_TIMEOUT_USE_DEFAULT, error);
	dbus_message_unref(message);
	if (error != NULL && dbus_error_is_set(error)) {
		if (reply)
			dbus_message_unref(reply);
		return GS_REPLY_ERROR;
	}

	if (reply == NULL)
		return GS_BAD_REPLY;

	dbus_message_iter_init(reply, &args);

	const char *request_id;
	dbus_message_iter_get_basic(&args, &request_id);

	dbus_message_unref(reply);

	__gs_claim_queue(session);
	struct __gs_Msg *iter = ((struct __gs_Queue*)session->_queue)->top;

	do {

		if (iter == NULL) {
			dbus_connection_read_write((DBusConnection*)session->connection, 1);
			reply = dbus_connection_pop_message((DBusConnection*)session->connection);
		} else
			reply = iter->message;

		if (reply != NULL && dbus_message_is_signal(reply, "org.freedesktop.portal.Request", "Response") && strcmp(dbus_message_get_path(reply), request_id) == 0) {
			if (iter != NULL)
				__gs_queue_pop_msg(session, iter);
			break;
		} else if (reply != NULL && iter == NULL && __gs_is_signal_relevant(session, reply))
			__gs_queue_push_msg(session, reply);

		if (iter)
			iter = iter->next;

	} while (1);

	__gs_release_queue(session);

	dbus_message_iter_init(reply, &args);

	int status;
	dbus_message_iter_get_basic(&args, &status);
	if (status != 0) {
		dbus_message_unref(reply);
		return GS_BAD_SIGNAL;
	}

	dbus_message_iter_next(&args);

	dbus_message_iter_recurse(&args, &array_iter);
	dbus_message_iter_recurse(&array_iter, &dict_iter);

	dbus_message_iter_next(&dict_iter);

	dbus_message_iter_recurse(&dict_iter, &variant_iter);

	*shortcut_list = NULL;
	*num = dbus_message_iter_get_element_count(&variant_iter);

	if (*num == 0)
		return 0;

	*shortcut_list = calloc(*num, sizeof(struct gs_Shortcut));

	dbus_message_iter_recurse(&variant_iter, &array_iter);

	for (int i = 0; i < *num; i++) {

		(*shortcut_list)[i].description = NULL;
		(*shortcut_list)[i].trigger = NULL;

		const char *result;

		dbus_message_iter_recurse(&array_iter, &struct_iter);

		dbus_message_iter_get_basic(&struct_iter, &result);
		(*shortcut_list)[i].name = malloc(strlen(result) + 1);
		strcpy((*shortcut_list)[i].name, result);

		dbus_message_iter_next(&struct_iter);

		dbus_message_iter_recurse(&struct_iter, &subarray_iter);

		const char *options[] = {
			"description",
			"trigger_description"
		};
		const char *option_key;

		for (int z = 0; z < sizeof(options) / sizeof(const char*); z++) {

			dbus_message_iter_recurse(&subarray_iter, &dict_iter);

			dbus_message_iter_get_basic(&dict_iter, &option_key);

			dbus_message_iter_next(&dict_iter);

			dbus_message_iter_recurse(&dict_iter, &variant_iter);

			dbus_message_iter_get_basic(&variant_iter, &result);

			if (strcmp(option_key, options[0]) == 0) {
				(*shortcut_list)[i].description = malloc(strlen(result) + 1);
				strcpy((*shortcut_list)[i].description, result);
			} else if (strcmp(option_key, options[1]) == 0) {
				(*shortcut_list)[i].trigger = malloc(strlen(result + 1));
				strcpy((*shortcut_list)[i].trigger, result);
			}

			dbus_message_iter_next(&subarray_iter);

		}

		dbus_message_iter_next(&array_iter);

	}

	dbus_message_unref(reply);

	return 0;

}

int gs_GetActivated(struct gs_Session *session, const char **shortcut_id, uint64_t *timestamp, void *error) {

	if (error != NULL)
		dbus_error_init(error);

	DBusMessage *reply;

	__gs_claim_queue(session);
	struct __gs_Msg *iter = ((struct __gs_Queue*)session->_queue)->top;

	do {

		if (iter == NULL) {
			dbus_connection_read_write((DBusConnection*)session->connection, 1);
			reply = dbus_connection_pop_message((DBusConnection*)session->connection);
		} else
			reply = iter->message;

		if (reply == NULL) {
			*shortcut_id = NULL;
			if (timestamp)
				*timestamp = 0;
			__gs_release_queue(session);
			return 0;
		}

		if (__gs_is_signal_relevant(session, reply))
			if (dbus_message_is_signal(reply, "org.freedesktop.portal.GlobalShortcuts", "Activated")) {
				if (iter != NULL)
					__gs_queue_pop_msg(session, iter);
				break;
			} else if (reply != NULL && iter == NULL)
				__gs_queue_push_msg(session, reply);

		if (iter)
			iter = iter->next;

	} while (1);

	__gs_release_queue(session);

	DBusMessageIter args;
	dbus_message_iter_init(reply, &args);

	dbus_message_iter_next(&args);
	
	const char *result;
	dbus_message_iter_get_basic(&args, &result);
	*shortcut_id = malloc(strlen(result) + 1);
	strcpy(*shortcut_id, result);

	if (timestamp) {
		
		dbus_message_iter_next(&args);

		uint64_t result;
		dbus_message_iter_get_basic(&args, &result);

		*timestamp = result;

	}

	dbus_message_unref(reply);

	return 0;

}

int gs_GetDeactivated(struct gs_Session *session, const char **shortcut_id, uint64_t *timestamp, void *error) {

	if (error != NULL)
		dbus_error_init(error);

	DBusMessage *reply;

	__gs_claim_queue(session);
	struct __gs_Msg *iter = ((struct __gs_Queue*)session->_queue)->top;

	do {

		if (iter == NULL) {
			dbus_connection_read_write((DBusConnection*)session->connection, 1);
			reply = dbus_connection_pop_message((DBusConnection*)session->connection);
		} else
			reply = iter->message;

		if (reply == NULL) {
			*shortcut_id = NULL;
			if (timestamp)
				*timestamp = 0;
			__gs_release_queue(session);
			return 0;
		}

		if (__gs_is_signal_relevant(session, reply))
			if (dbus_message_is_signal(reply, "org.freedesktop.portal.GlobalShortcuts", "Deactivated")) {
				if (iter != NULL)
					__gs_queue_pop_msg(session, iter);
				break;
			} else if (reply != NULL && iter == NULL)
				__gs_queue_push_msg(session, reply);

		if (iter)
			iter = iter->next;

	} while (1);

	__gs_release_queue(session);

	DBusMessageIter args;
	dbus_message_iter_init(reply, &args);

	dbus_message_iter_next(&args);
	
	const char *result;
	dbus_message_iter_get_basic(&args, &result);
	*shortcut_id = malloc(strlen(result) + 1);
	strcpy(*shortcut_id, result);

	if (timestamp) {
		
		dbus_message_iter_next(&args);

		uint64_t result;
		dbus_message_iter_get_basic(&args, &result);

		*timestamp = result;

	}

	dbus_message_unref(reply);

	return 0;

}

int gs_GetShortcutsChanged(struct gs_Session *session, struct gs_Shortcut **shortcut_list, int *num, void *error) {

	if (error != NULL)
		dbus_error_init(error);

	DBusMessage *reply;

	__gs_claim_queue(session);
	struct __gs_Msg *iter = ((struct __gs_Queue*)session->_queue)->top;

	do {

		if (iter == NULL) {
			dbus_connection_read_write((DBusConnection*)session->connection, 1);
			reply = dbus_connection_pop_message((DBusConnection*)session->connection);
		} else
			reply = iter->message;

		if (reply == NULL) {
			*shortcut_list = NULL;
			*num = 0;
			__gs_release_queue(session);
			return 0;
		}

		if (__gs_is_signal_relevant(session, reply))
			if (dbus_message_is_signal(reply, "org.freedesktop.portal.GlobalShortcuts", "ShortcutsChanged")) {
				if (iter != NULL)
					__gs_queue_pop_msg(session, iter);
				break;
			} else if (reply != NULL && iter == NULL)
				__gs_queue_push_msg(session, reply);

		if (iter)
			iter = iter->next;

	} while (1);

	__gs_release_queue(session);

	DBusMessageIter args;
	DBusMessageIter array_iter;
	DBusMessageIter struct_iter;
	DBusMessageIter subarray_iter;
	DBusMessageIter dict_iter;
	DBusMessageIter variant_iter;

	dbus_message_iter_init(reply, &args);

	dbus_message_iter_next(&args);

	*shortcut_list = NULL;
	*num = dbus_message_iter_get_element_count(&args);

	if (*num == 0)
		return 0;

	*shortcut_list = calloc(*num, sizeof(struct gs_Shortcut));

	dbus_message_iter_recurse(&args, &array_iter);

	for (int i = 0; i < *num; i++) {

		(*shortcut_list)[i].description = NULL;
		(*shortcut_list)[i].trigger = NULL;

		const char *result;

		dbus_message_iter_recurse(&array_iter, &struct_iter);

		dbus_message_iter_get_basic(&struct_iter, &result);
		(*shortcut_list)[i].name = malloc(strlen(result) + 1);
		strcpy((*shortcut_list)[i].name, result);

		dbus_message_iter_next(&struct_iter);

		dbus_message_iter_recurse(&struct_iter, &subarray_iter);

		const char *options[] = {
			"description",
			"trigger_description"
		};
		const char *option_key;

		for (int z = 0; z < sizeof(options) / sizeof(const char*); z++) {

			dbus_message_iter_recurse(&subarray_iter, &dict_iter);

			dbus_message_iter_get_basic(&dict_iter, &option_key);

			dbus_message_iter_next(&dict_iter);

			dbus_message_iter_recurse(&dict_iter, &variant_iter);

			dbus_message_iter_get_basic(&variant_iter, &result);

			if (strcmp(option_key, options[0]) == 0) {
				(*shortcut_list)[i].description = malloc(strlen(result) + 1);
				strcpy((*shortcut_list)[i].description, result);
			} else if (strcmp(option_key, options[1]) == 0) {
				(*shortcut_list)[i].trigger = malloc(strlen(result + 1));
				strcpy((*shortcut_list)[i].trigger, result);
			}

			dbus_message_iter_next(&subarray_iter);

		}

		dbus_message_iter_next(&array_iter);

	}

	dbus_message_unref(reply);

	return 0;

}