#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#include "lib-support.h"

// Cấu trúc đại diện cho một file ELF được load
struct __DLoader_Internal {
    uintptr_t load_bias;    // Độ lệch địa chỉ khi mapping ELF vào bộ nhớ
    void *entry;            // Entry point (struct program_header)
    ElfW_Dyn *pt_dynamic;   // Con trỏ tới dynamic section
    void **dt_pltgot;       // Bảng PLT/GOT
    plt_resolver_t user_plt_resolver;   // Hàm resolver tự định nghĩa
    void *user_plt_resolver_handle;     // handle (context) truyền cho resolver
};

// Hàm thay thế memset(buf, 0, n)
static void my_bzero(void *buf, size_t n){
    char *p = buf;
    while (n-- > 0) 
        *p++ = 0;
}

// Hàm thay thế strlen() - đếm độ dài chuỗi C
// Tránh dùng hàm strlen trong libc vì nó có thể là symbol chưa được resolve
static size_t my_strlen(const char *s){
    size_t n = 0;
    while (*s++ != '\0') 
        ++n;
    return n;
}

// Tạo một phần tử iovec từ chuỗi hằng
// cond = 1 → dùng độ dài thực sự (bỏ '\0'), ngược lại = 0 thì độ dài là 0
#define STRING_IOV(string_constant, cond) \
        {(void *)string_constant, cond ? (sizeof(string_constant) - 1) : 0}

// Hàm báo lỗi và kết thúc chương trình
// Format: [loader] <filename>: <message>
// Dùng writev thay vì printf để tránh phụ thuộc vào libc
__attribute__((noreturn))
static void fail(const char *filename, const char *message)
{
    struct iovec iov[] = {
        STRING_IOV("[loader] ", 1),
        {(void *) filename, my_strlen(filename)},
        STRING_IOV(": ", 1),
        {(void *) message, my_strlen(message)},
        {NULL, 0},
        {"\n", 1},
    };
    const int niov = sizeof(iov) / sizeof(iov[0]);
    writev(2, iov, niov);   
    exit(2);
}

// Chuyển p_flags của program header thành mmap protection
static int prot_from_phdr(const ElfW_Phdr *phdr){
    int prot = 0;
    if (phdr->p_flags & PF_R) prot |= PROT_READ;
    if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
    if (phdr->p_flags & PF_X) prot |= PROT_EXEC;
    return prot;
}

// Làm tròn lên đến bội số của size
static inline uintptr_t round_up(uintptr_t value, uintptr_t size){
    return (value + size - 1) & -size;
}

// Làm tròn xuống đến bội số của size
static inline uintptr_t round_down(uintptr_t value, uintptr_t size){
    return value & -size;
}


// Tìm kiếm một entry cụ thể trong dynamic section
ElfW_Word get_dynamic_entry(ElfW_Dyn *dynamic, int field){
    for (; dynamic->d_tag != DT_NULL; dynamic++){
        if (dynamic->d_tag == field)
            return dynamic->d_un.d_val;
    }
    return 0;
}

// PLT Trampoline - assembly code để xử lý PLT resolution
void plt_trampoline();
asm(".pushsection .text," ax "\n"
    "plt_trampoline:"                        "\n"
    POP_S(%rdi)    /* handle */         "\n"
    POP_S(%rsi)    /* import_id */      "\n"
    PUSH_STACK_STATE                         "\n"
    CALL(system_plt_resolver)                "\n"
    POP_STACK_STATE                          "\n"
    JMP_REG(%rax)  /* Nhảy đến địa chỉ hàm đã resolve*/    "\n"
    ".popsection"                            "\n");

void *system_plt_resolver(dloader_p o, int import_id){
    return o->user_plt_resolver(o->user_plt_resolver_handle, import_id);
}

// API chính: Load file ELF 
dloader_p api_load(const char *filename){
    size_t pagesize = 0x1000;   // 4KB page size

    // Mở và đọc ELF header
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fail(filename, "Failed to open");
    }
    ElfW_Ehdr ehdr;
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != sizeof(ehdr)) {
        fail(filename, "Failed to read ELF header");
        close(fd);
    }

    // Kiểm tra magic bytes và version của ELF
    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr.e_ident[EI_MAG3] != ELFMAG3 ||
        ehdr.e_version != EV_CURRENT || ehdr.e_ehsize != sizeof(ehdr) ||
        ehdr.e_phentsize != sizeof(ElfW_Phdr))
        fail(filename, "File has no valid ELF header!");
    
    // Kiểm tra kiến trúc CPU
    if (ehdr.e_machine != EM_X86_64) fail(filename, "ELF file has wrong architecture! ");

    // Không hỗ trợ shared library (ET_DYN)
    if (ehdr.e_type != ET_DYN)
        fail(filename, "ELF file not ET_DYN! ");

    // Đọc program headers
    ElfW_Phdr* phdr = malloc(ehdr.e_phnum * sizeof(ElfW_Phdr));
    if (pread(fd, phdr, ehdr.e_phnum * sizeof(ElfW_Phdr), ehdr.e_phoff) != ehdr.e_phnum * sizeof(ElfW_Phdr)) {
        fail(filename, "Failed to read program headers");
        free(phdr);
        close(fd);
    } 
  
    // Tìm segment PT_LOAD đầu tiên và cuối
    const ElfW_Phdr *first_load = NULL;
    const ElfW_Phdr *last_load = NULL;
    size_t i = 0;
    for (i = 0; i < ehdr.e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            if (!first_load)
                first_load = &phdr[i];
            last_load = &phdr[i];
        }
    }
    if (!first_load) {
        printf("No LOAD segments found\n");
        free(phdr);
        close(fd);
    }

    // Tính kích thước bộ nhớ cần thiết cho các PT_LOAD segment
    size_t span = last_load->p_vaddr + last_load->p_memsz - first_load->p_vaddr;

    /*
     * Map segment đầu tiên và reserve không gian cho các segment còn lại
     * cũng như các khoảng trống giữa các segment
     */
    ElfW_Addr desired_addr = round_down(first_load->p_vaddr, pagesize);
    ElfW_Addr file_offset = round_down(first_load->p_offset, pagesize);
    const uintptr_t mapping = (uintptr_t) mmap((void *) desired_addr, span, 
                                prot_from_phdr(first_load), MAP_PRIVATE, fd, file_offset);

    // Tính toán load_bias 
    const ElfW_Addr load_bias = mapping - desired_addr;
    
    // Theo dõi segment read-only để xử lý relocation
    const ElfW_Phdr *ro_load = NULL;
    if (!(first_load->p_flags & PF_W))
        ro_load = first_load;

    // Xử lý BSS section của segment đầu tiên
    if (first_load->p_memsz > first_load->p_filesz) {
        // Địa chỉ kết thúc dữ liệu file thực tế
        ElfW_Addr file_end = first_load->p_vaddr + load_bias + first_load->p_filesz;

        // Địa chỉ cuối trang chứa file_end
        ElfW_Addr file_page_end = round_up(file_end, pagesize);

        // Địa chỉ cuối của toàn bộ segment (bao gồm BSS)
        ElfW_Addr page_end = round_up(first_load->p_vaddr + load_bias + first_load->p_memsz, pagesize);

        // Map các trang hoàn chỉnh với anonymous memory (zero-filled)
        if (page_end > file_page_end)
            mmap((void *)file_page_end,
                 page_end - file_page_end, prot_from_phdr(first_load), 
                 MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);

        // Zero-fill phần lẻ trong trang cuối
        if (file_page_end > file_end && (first_load->p_flags & PF_W))
            my_bzero((void *)file_end, file_page_end - file_end);
    }

    ElfW_Addr last_end = first_load->p_vaddr + load_bias + first_load->p_memsz;

    // Map các segment còn lại 
    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && &phdr[i] != first_load) {

            last_end = phdr[i].p_vaddr + load_bias + phdr[i].p_memsz;
            ElfW_Addr start = round_down(phdr[i].p_vaddr + load_bias, pagesize);
            ElfW_Addr end = round_up(last_end, pagesize);

            // Map segment hiện tại
            mmap((void *)start, end - start,
                 prot_from_phdr(&phdr[i]), MAP_PRIVATE | 
                 MAP_FIXED, fd, 
                 round_down(phdr[i].p_offset, pagesize));

            // Xử lý BSS cho segment này
            ElfW_Addr file_end = phdr[i].p_vaddr + load_bias + phdr[i].p_filesz;
            ElfW_Addr file_page_end = round_up(file_end, pagesize);
            if (end > file_page_end)
            mmap((void *)file_page_end,
                 end - file_page_end, prot_from_phdr(&phdr[i]), 
                 MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
            if (file_page_end > file_end && (phdr[i].p_flags & PF_W))
                my_bzero((void *)file_end, file_page_end - file_end);

            // Cập nhật segment read-only
            if (!(phdr[i].p_flags & PF_W) && !ro_load)
                ro_load = &phdr[i];
        }
    }

    // Tìm PT_DYNAMIC header để lấy thông tin
    ElfW_Dyn *dynamic = NULL;
    for (int i = 0; i < ehdr.e_phnum; ++i){
        if (phdr[i].p_type == PT_DYNAMIC){
            assert(dynamic == NULL);    // Chỉ có một PT_DYNAMIC
            dynamic = (ElfW_Dyn *)(load_bias + phdr[i].p_vaddr);
        }
    }
    assert(dynamic != NULL);
    /*
     * Xử lý relocation entries
     * Đây là các entry cần được điều chỉnh địa chỉ sau khi load
     */
    ElfW_Addr ro_start = ro_load->p_offset + load_bias;
    ElfW_Addr ro_end = ro_start + ro_load->p_memsz;

    // Lấy bảng relocation từ dynamic section
    ElfW_Rela *relocs =
        (ElfW_Rela *)(load_bias + get_dynamic_entry(dynamic, DT_RELA));
    size_t relocs_size = get_dynamic_entry(dynamic, DT_RELASZ);
    
    // Xử lý từng relocation entry
    for (size_t i = 0; i < relocs_size / sizeof(ElfW_Rela); i++) {
        ElfW_Rela *reloc = &relocs[i];
        int reloc_type = ELF64_R_TYPE(reloc->r_info);
        if (reloc_type == R_X86_64_RELATIVE) {
            // Địa chỉ cần được relocate
            ElfW_Addr* addr = (ElfW_Addr*)(load_bias + relocs[i].r_offset);
            // Nếu addr nằm trong vùng read-only (.text), tạm thời
            // cấp quyền WRITE để sửa đổi, sau đó restore lại quyền cũ
            if ((intptr_t) addr < ro_end && (intptr_t) addr >= ro_start) {
                mprotect((void*) round_down((intptr_t) addr, pagesize), pagesize, PROT_WRITE);
                *addr += load_bias; // Điều chỉnh địa chỉ
                mprotect((void*) round_down((intptr_t)addr, pagesize), pagesize, prot_from_phdr(ro_load));
            }
            else
                *addr += load_bias; // Điều chỉnh địa chỉ trực tiếp
        }
    } 

    // Tạo object để quản lý ELF đã load
    dloader_p o = malloc(sizeof(struct __DLoader_Internal));
    assert(o != NULL);
    o->load_bias = load_bias;
    o->entry = (void *)(ehdr.e_entry + load_bias);  // Entry point đã điều chỉnh   
    o->pt_dynamic = dynamic;
    o->dt_pltgot = NULL;
    
    // Lấy thông tin PLT/GOT nếu có
    uintptr_t pltgot = get_dynamic_entry(dynamic, DT_PLTGOT);
    if (pltgot != 0){
        o->dt_pltgot = (void **)(pltgot + load_bias);
    }

    close(fd);
    printf("=== INFO ===\n");
    printf("load_bias = %p\n", (void *)o->load_bias); /////////
    return o;
}

// API: Lấy user_info từ program_header của ELF đã load
void *api_get_user_info(dloader_p o)
{
    return ((struct program_header *)(o->entry))->user_info;
}

// API: Đăng ký resolver function cho PLT lazy binding
void api_set_plt_resolver(dloader_p o, plt_resolver_t resolver, void *handle)
{
    struct program_header *PROG_HEADER = o->entry;

    // Gán địa chỉ plt_trampoline 
    *PROG_HEADER->plt_trampoline = (void *) plt_trampoline;

    // Gán handle để truyền cho resolver
    *PROG_HEADER->plt_handle = o;

    // Lưu resolver function và handle
    o->user_plt_resolver = resolver;
    o->user_plt_resolver_handle = handle;
}

// API: Gán địa chỉ hàm thực cho một PLT entry cụ thể
void api_set_plt_entry(dloader_p o, int import_id, void *func)
{
    // Cập nhật PLTGOT entry để trỏ trực tiếp đến hàm thực
    // Lần gọi tiếp theo sẽ nhảy thẳng đến đây, không qua resolver
    ((struct program_header *)(o->entry))->pltgot[import_id] = func;
}

// API: Lấy con trỏ đến bảng PLTGOT
void **api_get_pltgot(dloader_p o)
{
    return ((struct program_header *)(o->entry))->pltgot;
}

// Cấu trúc API chính được export
struct __DLoader_API__ DLoader = {
    .load = api_load,
    .get_info = api_get_user_info,
    .set_plt_resolver = api_set_plt_resolver,
    .set_plt_entry = api_set_plt_entry,
    .get_pltgot = api_get_pltgot, 
};