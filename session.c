#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <dbus/dbus.h>

#define PORTAL_TARGET "org.freedesktop.portal.Desktop"
#define PORTAL_OBJECT "/org/freedesktop/portal/desktop"
#define PORTAL_INTERFACE "org.freedesktop.portal.GlobalShortcuts"

struct gs_Session {
	DBusConnection *connection;
	const char *session_id;
	char token_string[256];
};

struct gs_Shortcut {
	const char *name;
	const char *description;
	const char *trigger;
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

int gs_CreateSession(struct gs_Session *session, const char *app_id, DBusError *error) {

	if (error != NULL)
		dbus_error_init(error);

	session->connection = dbus_bus_get(DBUS_BUS_SESSION, error);
	if (error != NULL && dbus_error_is_set(error)) {
		dbus_connection_close(session->connection);
		session->connection = NULL;
		return CONNECTION_ERROR;
	}

	if (session->connection == NULL) {
		dbus_connection_close(session->connection);
		session->connection = NULL;
		return BAD_CONNECTION;
	}

	DBusMessage *message;
	message = dbus_message_new_method_call(
		PORTAL_TARGET,
		PORTAL_OBJECT,
		PORTAL_INTERFACE,
		"CreateSession"
	);
	if (message == NULL) {
		dbus_connection_close(session->connection);
		session->connection = NULL;
		return MSG_CREATION_ERROR;
	}

	unsigned random_id;
	getrandom(&random_id, sizeof(random_id), GRND_NONBLOCK);

	snprintf(session->token_string, sizeof(session->token_string), "gsbus_%d\0", random_id % 10000);
	const char *token_string_ptr = session->token_string;

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
	reply = dbus_connection_send_with_reply_and_block(session->connection, message, DBUS_TIMEOUT_USE_DEFAULT, error);
	dbus_message_unref(message);
	if (error != NULL && dbus_error_is_set(error)) {
		if (reply)
			dbus_message_unref(reply);
		dbus_connection_unref(session->connection);
		session->connection = NULL;
		return REPLY_ERROR;
	}

	if (reply == NULL) {
		dbus_connection_unref(session->connection);
		session->connection = NULL;
		return BAD_REPLY;
	}

	dbus_message_iter_init(reply, &args);

	const char *request_id;
	dbus_message_iter_get_basic(&args, &request_id);

	dbus_message_unref(reply);

	char match_rule[256];
	snprintf(match_rule, sizeof(match_rule), "type='signal',interface='org.freedesktop.portal.Request',path='%s'", request_id);

	dbus_bus_add_match(session->connection, match_rule, error);
	if (error != NULL && dbus_error_is_set(error)) {
		dbus_connection_close(session->connection);
		session->connection = NULL;
		return MATCH_RULE_ERROR;
	}

	dbus_connection_flush(session->connection);

	do {
		dbus_connection_read_write(session->connection, 0);
		reply = dbus_connection_pop_message(session->connection);
	} while (reply == NULL || !dbus_message_is_signal(reply, "org.freedesktop.portal.Request", "Response"));

	dbus_bus_remove_match(session->connection, match_rule, error);
	if (error != NULL && dbus_error_is_set(error)) {
		dbus_message_unref(reply);
		dbus_connection_close(session->connection);
		session->connection = NULL;
		return MATCH_RULE_ERROR;
	}

	dbus_message_iter_init(reply, &args);

	int status;
	dbus_message_iter_get_basic(&args, &status);
	if (status != 0) {
		dbus_message_unref(reply);
		dbus_connection_close(session->connection);
		session->connection = NULL;
		return BAD_SIGNAL;
	}

	dbus_message_iter_next(&args);

	dbus_message_iter_recurse(&args, &array_iter);
	dbus_message_iter_recurse(&array_iter, &dict_iter);

	dbus_message_iter_next(&dict_iter);

	dbus_message_iter_recurse(&dict_iter, &variant_iter);

	dbus_message_iter_get_basic(&variant_iter, &session->session_id);

	dbus_message_unref(reply);
	
	return 0;

}

void gs_CloseSession(struct gs_Session *session) {

	if (session == NULL)
		return;

	if (session->connection && dbus_connection_get_is_connected(session->connection)) {

		if (session->connection) {

			DBusMessage *message = dbus_message_new_method_call(
				PORTAL_TARGET,
				session->session_id,
				"org.freedesktop.portal.Session",
				"Close"
			);

			dbus_connection_send(session->connection, message, NULL);

		}

		dbus_connection_unref(session->connection);

	}

	session->session_id = NULL;

}

int gs_BindShortcuts(struct gs_Session *session, struct gs_Shortcut *shortcut_list, int num, DBusError *error) {

	if (error != NULL)
		dbus_error_init(error);

	DBusMessage *message = dbus_message_new_method_call(
		PORTAL_TARGET,
		PORTAL_OBJECT,
		PORTAL_INTERFACE,
		"BindShortcuts"
	);

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
	do {
		snprintf(token_string, sizeof(token_string), "gsbus_%d\0", random_id % 10000);
	} while (strcmp(session->token_string, token_string) == 0);
	const char *token_string_ptr = token_string;

	dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &dict_key);

	dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_VARIANT, "s", &variant_iter);

	dbus_message_iter_append_basic(&variant_iter, DBUS_TYPE_STRING, &token_string_ptr);

	dbus_message_iter_close_container(&dict_iter, &variant_iter);
	dbus_message_iter_close_container(&array_iter, &dict_iter);
	dbus_message_iter_close_container(&args, &array_iter);

	DBusMessage *reply = dbus_connection_send_with_reply_and_block(session->connection, message, DBUS_TIMEOUT_USE_DEFAULT, error);
	dbus_message_unref(message);
	if (error != NULL && dbus_error_is_set(error)) {
		if (reply)
			dbus_message_unref(reply);
		return REPLY_ERROR;
	}

	if (reply == NULL)
		return BAD_REPLY;

	dbus_message_unref(reply);

	return 0;

}

int gs_ListShortcuts(struct gs_Session *session, struct gs_Shortcut **shortcut_list, int *num, DBusError *error) {

	if (error != NULL)
		dbus_error_init(error);

	DBusMessage *message = dbus_message_new_method_call(
		PORTAL_TARGET,
		PORTAL_OBJECT,
		PORTAL_INTERFACE,
		"ListShortcuts"
	);

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

	DBusMessage *reply = dbus_connection_send_with_reply_and_block(session->connection, message, DBUS_TIMEOUT_USE_DEFAULT, error);
	dbus_message_unref(message);
	if (error != NULL && dbus_error_is_set(error)) {
		if (reply)
			dbus_message_unref(reply);
		return REPLY_ERROR;
	}

	if (reply == NULL)
		return BAD_REPLY;

	dbus_message_iter_init(reply, &args);

	const char *request_id;
	dbus_message_iter_get_basic(&args, &request_id);

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
	if (error != NULL && dbus_error_is_set(error)) {
		dbus_message_unref(reply);
		return MATCH_RULE_ERROR;
	}

	dbus_message_iter_init(reply, &args);

	int status;
	dbus_message_iter_get_basic(&args, &status);
	if (status != 0) {
		dbus_message_unref(reply);
		return BAD_SIGNAL;
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
		(*shortcut_list)[i].name = result;

		dbus_message_iter_next(&struct_iter);

		dbus_message_iter_recurse(&struct_iter, &subarray_iter);

		const char *options[] = {
			"description",
			"preferred_trigger"
		};
		const char *option_key;

		for (int z = 0; z < sizeof(options) / sizeof(const char*); z++) {

			dbus_message_iter_recurse(&subarray_iter, &dict_iter);

			dbus_message_iter_get_basic(&dict_iter, &option_key);

			dbus_message_iter_next(&dict_iter);

			dbus_message_iter_recurse(&dict_iter, &variant_iter);

			dbus_message_iter_get_basic(&variant_iter, &result);

			if (strcmp(option_key, options[0]) == 0)
				(*shortcut_list)[i].description = result;
			else if (strcmp(option_key, options[1]) == 0)
				(*shortcut_list)[i].trigger = result;

			dbus_message_iter_next(&subarray_iter);

		}

		dbus_message_iter_next(&array_iter);

	}

	return 0;

}

int main() {

	struct gs_Session session;
	DBusError error;
	printf("%d\n", gs_CreateSession(&session, "GS_TEST", &error));

	if (dbus_error_is_set(&error)) {
		puts(error.message);
		dbus_error_free(&error);
		return 0;
	}

	puts(session.session_id);
	// while (1);

	struct gs_Shortcut shortcuts[] = {
		{
			.name = "BANANA",
			.description = "Fill the form here (no scam)",
			.trigger = "LOGO+M"
		},
		{
			.name = "BANANA_2",
			.description = "Fill the form here (no scam)",
			.trigger = "LOGO+N"
		}
	};

	printf("%d\n", gs_BindShortcuts(&session, shortcuts, sizeof(shortcuts) / sizeof(struct gs_Shortcut), &error));

	if (dbus_error_is_set(&error)) {
		puts(error.message);
		dbus_error_free(&error);
		return 0;
	}

	struct gs_Shortcut *shortcut_list;
	int num;
	printf("%d\n", gs_ListShortcuts(&session, &shortcut_list, &num, &error));

	if (dbus_error_is_set(&error)) {
		puts(error.message);
		dbus_error_free(&error);
		return 0;
	}

	for (int i = 0; i < num; i++)
		printf("NAME:[%s] DESCR:[%s] TRIG:[%s]\n", shortcut_list[i].name, shortcut_list[i].description, shortcut_list[i].trigger);

	gs_CloseSession(&session);

}