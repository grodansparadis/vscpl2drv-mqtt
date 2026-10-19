#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

int main(int argc, char **argv)
{
    const char *symbols[] = {
        "VSCPOpen", "VSCPClose", "VSCPWrite", "VSCPRead", "VSCPGetVersion"
    };
    size_t i;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <driver-library>\n", argv[0]);
        return EXIT_FAILURE;
    }

#ifdef _WIN32
    HMODULE driver = LoadLibraryExA(argv[1], NULL,
                                  LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                                  LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (driver == NULL) {
        fprintf(stderr, "Cannot load driver: Windows error %lu\n", GetLastError());
        return EXIT_FAILURE;
    }
#else
    void *driver = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (driver == NULL) {
        fprintf(stderr, "Cannot load driver: %s\n", dlerror());
        return EXIT_FAILURE;
    }
#endif

    for (i = 0; i < sizeof(symbols) / sizeof(symbols[0]); ++i) {
#ifdef _WIN32
        if (GetProcAddress(driver, symbols[i]) == NULL) {
#else
        if (dlsym(driver, symbols[i]) == NULL) {
#endif
            fprintf(stderr, "Missing driver export: %s\n", symbols[i]);
            return EXIT_FAILURE;
        }
    }

#ifdef _WIN32
    if (!FreeLibrary(driver)) {
        fprintf(stderr, "Cannot unload driver: Windows error %lu\n", GetLastError());
        return EXIT_FAILURE;
    }
#else
    if (dlclose(driver) != 0) {
        fprintf(stderr, "Cannot unload driver: %s\n", dlerror());
        return EXIT_FAILURE;
    }
#endif

    puts("Driver loads and exports all five Level II entry points.");
    return EXIT_SUCCESS;
}
