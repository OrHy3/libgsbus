# libgsbus
A C implementation of D-Bus GlobalShortcuts.

`libgsbus` is a simple API interface that aims to ease interactions with the `org.freedesktop.portal.GlobalShortcuts` D-Bus interface.

It's based on `libdbus` (or `dbus-1`) and has an internal queue system to make event handling as simple as it can be.

# Building
First inside the project directory run:
```bash
mkdir build && cd build
```
Then, to configure the project run:
```bash
cmake ..
```
This will generate the build files to compile the shared library `libgsbus.so`. If you want to generate the `libgsbus.a` static library instead run:
```bash
cmake .. -DBUILD_SHARED_LIBS=OFF
```
To complete the build process run:
```bash
make
```
If you want you can then install the library to your system (this will copy the library and header files to `/usr/lib` and `/usr/include`). To do so run:
```bash
sudo make install
```

# Usage
As previously said, `libgsbus` has an internal queue in every `gs_Session` object. It has some basic mutex-like functioning, but I won't recommend it to use a single `gs_Session` over many threads, I'd rather suggest you to create multiple separate objects.

Every program has to link against both `gsbus` and `dbus-1`.

The following code shows how to open a session and bind a shortcut.
The trigger's syntax follows the [shortcuts XDG specification](https://specifications.freedesktop.org/shortcuts-spec/latest/).
```c
#include <stdio.h>
#include <gsbus.h>

int main() {
	
	struct gs_Session session;

	gs_CreateSession(&session, "ExampleAppName", NULL);

	struct gs_Shortcut shortcuts[] = {
		{
			.name = "ExampleKey",
			.description = "This is an example shortcut",
			.trigger = "CTRL+SHIFT+LOGO+M"
		}
	};
	gs_BindShortcuts(&session, shortcuts, 1, NULL);

	gs_CloseSession(&session);

}
```
Here is the code if we wanted to evaluate the D-Bus error after connecting:
```c
#include <stdio.h>
#include <dbus/dbus.h>
#include <gsbus.h>

int main() {
	
	DBusError error;
	struct gs_Session session;

	dbus_error_init(&error);
	gs_CreateSession(&session, "ExampleAppName", &error);

	if (dbus_error_is_set(&error))
		printf("D-Bus error message: %s\n", error.message);

	gs_CloseSession(&session);

}
```
This last program lists the already registered shortcuts, runs a loop printing every shortcut event (and prints the timestamp for pressed keys only) and quits when a shortcut gets changed.
```c
#include <stdio.h>
#include <stdint.h>
#include <gsbus.h>

int main() {

	struct gs_Session session;

	gs_CreateSession(&session, "ExampleAppName", NULL);

	struct gs_Shortcut *shortcut_list;
	int num = 0;

	gs_ListShortcuts(&session, &shortcut_list, &num, NULL);

	for (int i = 0; i < num; i++)
		printf("Shortcut name: %s\nDescription: %s\nTriggers: %s\n\n",
			shortcut_list[i].name,
			shortcut_list[i].description,
			shortcut_list[i].trigger
		);

	const char *name;
	uint64_t timestamp;

	num = 0;

	while (num == 0) {

		gs_GetActivated(&session, &name, &timestamp, NULL);

		if (name != NULL)
			printf("Shortcut \"%s\" has been pressed at time %d\n", name, timestamp);


		gs_GetDeactivated(&session, &name, NULL, NULL);

		if (name != NULL)
			printf("Shortcut \"%s\" has been released\n", name);

		gs_GetShortcutsChanged(&session, &shortcut_list, &num, NULL);

		if (num > 0)
			break;

	}

	for (int i = 0; i < num; i++)
		printf("Shortcut name: %s\nDescription: %s\nTriggers: %s\n\n",
			shortcut_list[i].name,
			shortcut_list[i].description,
			shortcut_list[i].trigger
		);

	gs_CloseSession(&session);

}
```
If, for any reason, the event queue has to be emptied, one can do:
```c
gs_ClearQueue(&session);
```

# Error codes
Almost every function in this library retuns an `int` representing its execution code.
Value `0` means the function hasn't reported errors. For any other value, the `enum` definition is the following one:
```c
enum gs_ErrorCode {
	GS_CONNECTION_ERROR = 1, // error creating the connection, D-Bus error retrieved
	GS_BAD_CONNECTION,       // error creating the connection, no error retrieved
	GS_MSG_CREATION_ERROR,   // error creating the message, no error retrieved
	GS_REPLY_ERROR,          // error in the retrieved reply, D-Bus error retrieved
	GS_BAD_REPLY,            // error in the retrieved reply, no error retrieved
	GS_BAD_SIGNAL            // error in the retrieved Response (got non-zero value), no error retrieved
};
```
# Remarks
The GlobalShortcuts portal is meant to become a standard for every desktop environment, meaning every DE will have its own implementation following this standard. This allows the library to be usable even on Wayland, where GlobalShortcuts have been missing a long time. However, behavior can slightly differ across environments (I tested the library primarily on KDE).