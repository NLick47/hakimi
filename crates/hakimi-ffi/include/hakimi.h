#ifndef HAKIMI_H
#define HAKIMI_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(HAKIMI_STATIC)
#define HAKIMI_API
#elif defined(_WIN32)
#define HAKIMI_API __declspec(dllimport)
#else
#define HAKIMI_API __attribute__((visibility("default")))
#endif

typedef struct HakimiHandle HakimiHandle;

/* Create a runtime. config_dir may be NULL to use the platform data directory.
 * Returns NULL on failure; call hakimi_last_init_error() for a message. */
HAKIMI_API HakimiHandle *hakimi_init(const char *config_dir);

/* Start/stop the proxy, PAC takeover and background tasks. 0 on success. */
HAKIMI_API int hakimi_start(HakimiHandle *handle);
HAKIMI_API int hakimi_stop(HakimiHandle *handle);

/* Stop (if needed) and release the handle. */
HAKIMI_API void hakimi_free(HakimiHandle *handle);

/* Runtime status as a JSON object. Release with hakimi_free_string(). */
HAKIMI_API char *hakimi_status_json(HakimiHandle *handle);

/* Send a JSON command; returns {"ok":true,"result":...} or {"ok":false,"error":"..."}.
 * Release with hakimi_free_string(). */
HAKIMI_API char *hakimi_command_json(HakimiHandle *handle, const char *json);

/* Last error for this handle (NULL if none). Release with hakimi_free_string(). */
HAKIMI_API char *hakimi_last_error(HakimiHandle *handle);

/* Last hakimi_init failure (NULL if none). Release with hakimi_free_string(). */
HAKIMI_API char *hakimi_last_init_error(void);

/* Release a string returned by this library. NULL is a no-op. */
HAKIMI_API void hakimi_free_string(char *value);

#ifdef __cplusplus
}
#endif

#endif /* HAKIMI_H */
