#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "lib-support.h"

const char *test_import0() { return __func__; }
const char *test_import1() { return __func__; }

static int resolver_call_count = 0;
static int resolver_last_id = -1;

static void *plt_resolver(void *handle, int import_id)
{
    dloader_p o = handle;
    printf("resolver called for func #%i\n", import_id);
    resolver_call_count++;
    resolver_last_id = import_id;

    // Resolver trả về địa chỉ hàm thật
    void *funcs[] = {
        (void *) test_import0, (void *) test_import1,    // Hàm thật trong main program
    };
    void *func = funcs[import_id];

    // Gán pltgot[import_id] = địa chỉ hàm thật
    DLoader.set_plt_entry(o, import_id, func);
    return func;
}

int main()
{
    typedef const char *(*func_t)(void);
    
    dloader_p o = DLoader.load("test_lib.so");
    
    void **func_table = DLoader.get_info(o);

    // Lấy thông tin PLTGOT thông qua API 
    void **pltgot = DLoader.get_pltgot(o);//

    const char *(*func)(void);
    const char *result;

    printf("test_import0 address: %p\n", (void*)test_import0);
    printf("=================\n\n");


    printf("Imported functions >\n");
    
    DLoader.set_plt_resolver(o, plt_resolver,
                             /* user_plt_resolver_handle */ o);
    
    func = (func_t)func_table[0];
    printf("pltgot[0] before first call: %p\n", pltgot[0]);
    result = func();
    printf("pltgot[0] after first call: %p\n", pltgot[0]);
    assert(!strcmp(result, "test_import0"));
    assert(resolver_call_count == 1);
    assert(resolver_last_id == 0);
    resolver_call_count = 0;
    result = func(); //recall
    assert(!strcmp(result, "test_import0"));
    assert(resolver_call_count == 0);

    func = (func_t)func_table[1];
    result = func();
    assert(!strcmp(result, "test_import1"));
    assert(resolver_call_count == 1);
    assert(resolver_last_id == 1);
    resolver_call_count = 0;
    result = func();
    assert(!strcmp(result, "test_import1"));
    assert(resolver_call_count == 0);

    printf("PASS!\n");

    return 0;
}