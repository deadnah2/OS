#include "lib-support.h"

const char *import_func0();
const char *import_func1();

const char *test_import0()
{
    return import_func0();
}

const char *test_import1()
{
    return import_func1();
}

void *func_table[] = {
    test_import0, test_import1,
};

PLT_BEGIN;
PLT_ENTRY(0, import_func0);
PLT_ENTRY(1, import_func1);
DEFINE_HEADER(func_table);
