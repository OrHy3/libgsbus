#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <dbus/dbus.h>

#define PORTAL_TARGET "org.freedesktop.portal.Desktop"
#define PORTAL_OBJECT "/org/freedesktop/portal/desktop"
#define PORTAL_INTERFACE "org.freedesktop.portal.GlobalShortcuts"

struct gs_Session {
	DBusConnection *connection;
	const char *session_id;
};

enum gs_ErrorCode {
	CONNECTION_ERROR = 1,
	BAD_CONNECTION,
	MSG_CREATION_ERROR,
	REPLY_ERROR,
	BAD_REPLY,
	SIGNAL_ERROR,
	BAD_SIGNAL,
	MATCH_RULE_ERROR
};

int gs_open_session(struct gs_Session *session, DBusError *error) {

	if (error != NULL)
		dbus_error_init(error);

	session->connection = dbus_bus_get(DBUS_BUS_SESSION, error);
	if (error != NULL && dbus_error_is_set(error)) {
		return CONNECTION_ERROR;
	}

	if (session->connection == NULL)
		return BAD_CONNECTION;

	DBusMessage *message;
	message = dbus_message_new_method_call(
		PORTAL_TARGET,
		PORTAL_OBJECT,
		PORTAL_INTERFACE,
		"CreateSession"
	);
	if (message == NULL)
		return MSG_CREATION_ERROR;

	unsigned random_id;
	getrandom(&random_id, sizeof(random_id), GRND_NONBLOCK);

	char token_string[15];
	snprintf(token_string, sizeof(token_string), "gsbus_%d\0", random_id % 10000);
	const char *token_string_ptr = token_string;

	DBusMessageIter args;
	dbus_message_iter_init_append(message, &args);

	DBusMessageIter array_iter;
	dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sv}", &array_iter);

	DBusMessageIter dict_iter;
	dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &dict_iter);

	char *dict_keys[2] = {
		"handle_token",
		"session_handle_token"
	};

	dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &dict_keys[0]);

	DBusMessageIter variant_iter;
	dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_VARIANT, "s", &variant_iter);

	dbus_message_iter_append_basic(&variant_iter, DBUS_TYPE_STRING, &token_string_ptr);

	dbus_message_iter_close_container(&dict_iter, &variant_iter);
	dbus_message_iter_close_container(&array_iter, &dict_iter);

	dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &dict_iter);

	dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &dict_keys[1]);

	dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_VARIANT, "s", &variant_iter);

	dbus_message_iter_append_basic(&variant_iter, DBUS_TYPE_STRING, &token_string_ptr);

	dbus_message_iter_close_container(&dict_iter, &variant_iter);
	dbus_message_iter_close_container(&array_iter, &dict_iter);
	dbus_message_iter_close_container(&args, &array_iter);

	DBusMessage *reply;
	reply = dbus_connection_send_with_reply_and_block(session->connection, message, DBUS_TIMEOUT_USE_DEFAULT, error);
	dbus_message_unref(message);
	if (error != NULL && dbus_error_is_set(error))
		return REPLY_ERROR;

	if (reply == NULL)
		return BAD_REPLY;

	dbus_message_iter_init(reply, &args);

	const char *request_id;
	dbus_message_iter_get_basic(&args, &request_id);

	puts(request_id);

	dbus_message_unref(reply);

	char match_rule[256];
	snprintf(match_rule, sizeof(match_rule), "type='signal',interface='org.freedesktop.portal.Request',path='%s'", request_id);

	dbus_bus_add_match(session->connection, match_rule, error);
	if (error != NULL && dbus_error_is_set(error))
		return MATCH_RULE_ERROR;

	dbus_connection_flush(session->connection);

	do {
		dbus_connection_read_write(session->connection, 0);
		reply = dbus_connection_pop_message(session->connection);
	} while (reply == NULL || !dbus_message_is_signal(reply, "org.freedesktop.portal.Request", "Response"));

	dbus_bus_remove_match(session->connection, match_rule, error);
	if (error != NULL && dbus_error_is_set(error))
		return MATCH_RULE_ERROR;

	dbus_message_iter_init(reply, &args);

	int status;
	dbus_message_iter_get_basic(&args, &status);
	if (status != 0)
		return BAD_SIGNAL;

	dbus_message_iter_next(&args);

	dbus_message_iter_recurse(&args, &array_iter);
	dbus_message_iter_recurse(&array_iter, &dict_iter);

	dbus_message_iter_next(&dict_iter);

	dbus_message_iter_recurse(&dict_iter, &variant_iter);

	dbus_message_iter_get_basic(&variant_iter, &session->session_id);
	printf("%s\n", session->session_id);
	
	return 0;

}

int main() {
	struct gs_Session session;
	DBusError error;
	printf("%d\n", gs_open_session(&session, &error));

	if (dbus_error_is_set(&error))
		puts(error.message);
}