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

#define MAX_PHNUM 12

#define ELFW_R_TYPE(x) ELFW(R_TYPE)(x)
#define ELFW_R_SYM(x) ELFW(R_SYM)(x)

// Cấu trúc đại diện cho một file ELF được load
struct __DLoader_Internal {
    uintptr_t load_bias;    // Độ lệch địa chỉ khi mapping ELF vào bộ nhớ
                            // = địa chỉ thực tế - địa chỉ ảo trong ELF

    // Con trỏ tới entry point của ELF(struct program_header)
    // sau khi đã cộng thêm load_bias(điểm bắt đầu thực thi)
    void *entry;

    // Con trỏ tới bảng dynamic section (.dynamic) của ELF
    // Chứa thông tin như DT_PLTGOT, DT_JMPREL...
    ElfW(Dyn) *pt_dynamic;

    // Con trỏ đến bảng PLTGOT dùng cho PLT
    // Mỗi entry tương ứng với một hàm import
    void **dt_pltgot;

    // Bảng relocation có các PLT entries
    // Chứa thông tin về các hàm cần resolve
    ElfW_Reloc *dt_jmprel;

    size_t plt_entries; // Số lượng entry trong bảng PLT (số hàm import)

    // Hàm resolver tự định nghĩa
    // Khi gọi lần đầu, sẽ gọi hàm này để lấy địa chỉ của hàm thật
    plt_resolver_t user_plt_resolver;

    // Một handle (context) truyền cho resolver
    void *user_plt_resolver_handle;
};

/*
 * Trong các phiên bản glibc gần đây, ngay cả những hàm đơn giản như memset và strlen
 * cũng có thể phụ thuộc vào mã khởi động phức tạp, vì chúng được định nghĩa
 * bằng cách sử dụng STT_GNU_IFUNC.
 */

// Hàm thay thế memset(buf, 0, n) - ghi giá trị 0 vào n byte liên tiếp
// Tránh dùng memset từ libc vì có thể chưa được resolve
static inline 
void my_bzero(void *buf, size_t n)
{
    char *p = buf;
    while (n-- > 0)
        *p++ = 0;
}

// Hàm thay thế strlen() - đếm độ dài chuỗi C
// Tránh dùng hàm strlen trong libc vì nó có thể là symbol chưa được resolve
static inline 
size_t my_strlen(const char *s)
{
    size_t n = 0;
    while (*s++ != '\0')
        ++n;
    return n;
}

// Chuyển đổi số nguyên thành chuỗi để in ra với writev()
// Không dùng sprintf/snprintf vì các hàm này nằm trong stdio/libc
static void iov_int_string(int value, struct iovec *iov,
                           char *buf, size_t bufsz)
{
    // Bảng lookup để chuyển digit thành ký tự ('0' ở index 9)
    static const char *const lookup = "9876543210123456789" + 9;
    char *p = &buf[bufsz];   // Bắt đầu từ cuối buffer
    int negative = value < 0;

    // Chuyển số thành chuỗi (từ cuối về đầu)
    do{
        --p;
        *p = lookup[value % 10];
        value /= 10;
    } while (value != 0);
    if (negative)   // Thêm dấu âm nếu là số âm
        *--p = '-';
    iov->iov_base = p;  // Gán vị trí bắt đầu chuỗi
    iov->iov_len = &buf[bufsz] - p;  // Gán độ dài chuỗi
}

// Macro tiện ích để tạo một phần tử iovec từ chuỗi hằng
// cond = 1 → dùng độ dài thực sự (bỏ '\0'), ngược lại = 0 thì độ dài là 0
#define STRING_IOV(string_constant, cond) \
        {(void *)string_constant, cond ? (sizeof(string_constant) - 1) : 0}

// Hàm báo lỗi và kết thúc chương trình
// Format: [loader] <filename>: <message><item>=<value>
// Dùng writev thay vì printf để tránh phụ thuộc vào libc
__attribute__((noreturn))
static void fail(const char *filename, const char *message,
                 const char *item, int value)
{
    char valbuf[32];        // buffer để chứa số nguyên nếu cần
    struct iovec iov[] = {
        STRING_IOV("[loader] ", 1),
        {(void *) filename, my_strlen(filename)},
        STRING_IOV(": ", 1),
        {(void *) message, my_strlen(message)},
        {(void *) item, !item ? 0 : my_strlen(item)},
        STRING_IOV("=", !item),
        {NULL, 0},
        {"\n", 1},
    };
    const int niov = sizeof(iov) / sizeof(iov[0]);
    if (item != NULL)       // Nếu có item thì chuyển value thành chuỗi và gán vào iov[6]
        iov_int_string(value, &iov[6], valbuf, sizeof(valbuf));

    writev(2, iov, niov);   // Ghi toàn bộ chuỗi ra stderr (file descriptor 2)
    exit(2);                // Thoát chương trình với mã lỗi 2
}

// Chuyển đổi p_flags của program header thành protection flags cho mmap()
static int prot_from_phdr(const ElfW(Phdr) *phdr)
{
    int prot = 0;
    if (phdr->p_flags & PF_R)
        prot |= PROT_READ;
    if (phdr->p_flags & PF_W)
        prot |= PROT_WRITE;
    if (phdr->p_flags & PF_X)
        prot |= PROT_EXEC;
    return prot;
}

// Làm tròn lên đến bội số của size
static inline
uintptr_t round_up(uintptr_t value, uintptr_t size)
{
    return (value + size - 1) & -size;
}

// Làm tròn xuống đến bội số của size
static inline
uintptr_t round_down(uintptr_t value, uintptr_t size)
{
    return value & -size;
}

/*
 * Xử lý phần "bss" của segment - nơi memory size > file size
 * Cần zero-fill phần chênh lệch này.
 * 
 * - Với các trang nguyên: dùng mmap() anonymous pages
 * - Với phần lẻ trong trang: zero-fill trực tiếp bằng my_bzero()
 */
static void handle_bss(const ElfW(Phdr) *ph, ElfW(Addr) load_bias,
                       size_t pagesize)
{
    if (ph->p_memsz > ph->p_filesz){
        // Địa chỉ kết thúc dữ liệu file thực tế
        ElfW(Addr) file_end = ph->p_vaddr + load_bias + ph->p_filesz;

        // Địa chỉ cuối trang chứa file_end
        ElfW(Addr) file_page_end = round_up(file_end, pagesize);

        // Địa chỉ cuối của toàn bộ segment (bao gồm BSS)
        ElfW(Addr) page_end =
            round_up(ph->p_vaddr + load_bias + ph->p_memsz, pagesize);
        
        // Map các trang hoàn chỉnh với anonymous memory (zero-filled)
        if (page_end > file_page_end)
            mmap((void *)file_page_end,
                 page_end - file_page_end, prot_from_phdr(ph), 
                 MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);

        // Zero-fill phần lẻ trong trang cuối (chỉ khi segment có quyền WRITE)
        if (file_page_end > file_end && (ph->p_flags & PF_W))
            my_bzero((void *)file_end, file_page_end - file_end);
    }
}

// Tìm kiếm một entry cụ thể trong dynamic section
ElfW(Word) get_dynamic_entry(ElfW(Dyn) *dynamic, int field)
{
    for (; dynamic->d_tag != DT_NULL; dynamic++){
        if (dynamic->d_tag == field)
            return dynamic->d_un.d_val;
    }
    return 0;
}

/*
 * PLT Trampoline - assembly code để xử lý PLT resolution
 * Sử dụng các macro được định nghĩa trong arch/ để hỗ trợ các kiến trúc khác nhau
 */
void plt_trampoline();
asm(".pushsection .text,\"ax\",\"progbits\"" "\n"
    "plt_trampoline:"                        "\n"
    POP_S(REG_ARG_1)    /* handle */         "\n"
    POP_S(REG_ARG_2)    /* import_id */      "\n"
    PUSH_STACK_STATE                         "\n"
    CALL(system_plt_resolver)                "\n"
    POP_STACK_STATE                          "\n"
    JMP_REG(REG_RET)  /* Nhảy đến địa chỉ hàm đã resolve*/    "\n"
    ".popsection"                            "\n");

void *system_plt_resolver(dloader_p o, int import_id)
{
    return o->user_plt_resolver(o->user_plt_resolver_handle, import_id);
}

// API chính: Load một file ELF và chuẩn bị để thực thi
dloader_p api_load(const char *filename)
{
    size_t pagesize = 0x1000;   // 4KB page size
    int fd = open(filename, O_RDONLY);

    // Đọc ELF header
    ElfW(Ehdr) ehdr;
    pread(fd, &ehdr, sizeof(ehdr), 0);

    // Kiểm tra magic bytes và version của ELF
    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr.e_ident[EI_MAG3] != ELFMAG3 ||
        ehdr.e_version != EV_CURRENT || ehdr.e_ehsize != sizeof(ehdr) ||
        ehdr.e_phentsize != sizeof(ElfW(Phdr)))
        fail(filename, "File has no valid ELF header!", NULL, 0);
    
    // Kiểm tra kiến trúc CPU có được hỗ trợ không
    switch (ehdr.e_machine) {
    case EM_X86_64:
    case EM_ARM:
    case EM_AARCH64:
        break;
    default:
        fail(filename, "ELF file has wrong architecture! ",
             "e_machine", ehdr.e_machine);
        break;
    }

    // Đọc program headers
    ElfW(Phdr) phdr[MAX_PHNUM];
    if (ehdr.e_phnum > sizeof(phdr) / sizeof(phdr[0]) || ehdr.e_phnum < 1)
        fail(filename, "ELF file has unreasonable ", "e_phnum", ehdr.e_phnum);

    // Không hỗ trợ shared library (ET_DYN)
    if (ehdr.e_type != ET_DYN)
        fail(filename, "ELF file not ET_DYN! ", "e_type", ehdr.e_type);

    pread(fd, phdr, sizeof(phdr[0]) * ehdr.e_phnum, ehdr.e_phoff);

    // Tìm segment PT_LOAD đầu tiên
    size_t i = 0;
    while (i < ehdr.e_phnum && phdr[i].p_type != PT_LOAD)
        ++i;
    if (i == ehdr.e_phnum)
        fail(filename, "ELF file has no PT_LOAD header!", NULL, 0);
       
    /* 
     * ELF yêu cầu các PT_LOAD segment phải được sắp xếp theo thứ tự tăng dần của p_vaddr.
     * Tìm segment cuối cùng để tính toán kích thước toàn bộ image.
     */
    const ElfW(Phdr) *first_load = &phdr[i];
    const ElfW(Phdr) *last_load = &phdr[ehdr.e_phnum - 1];
    while (last_load > first_load && last_load->p_type != PT_LOAD)
        --last_load;

    // Tính tổng kích thước bộ nhớ cần thiết cho tất cả các PT_LOAD segment
    size_t span = last_load->p_vaddr + last_load->p_memsz - first_load->p_vaddr;

    /*
     * Map segment đầu tiên và reserve không gian cho các segment còn lại
     * cũng như các khoảng trống giữa các segment
     */
    const uintptr_t mapping =
        (uintptr_t) mmap((void *) round_down(first_load->p_vaddr, pagesize), 
                        span, prot_from_phdr(first_load), MAP_PRIVATE, fd, 
                        round_down(first_load->p_offset, pagesize));

    // Tính toán load_bias - độ lệch giữa địa chỉ thực tế và địa chỉ ảo trong ELF
    const ElfW(Addr) load_bias =
        mapping - round_down(first_load->p_vaddr, pagesize);

    // Kiểm tra program headers có nằm trong segment đầu tiên không
    if (first_load->p_offset > ehdr.e_phoff ||
        first_load->p_filesz <
            ehdr.e_phoff + (ehdr.e_phnum * sizeof(ElfW(Phdr))))
        fail(filename, "First load segment of ELF does not contain phdrs!", 
            NULL, 0);
    
    // Theo dõi segment read-only để xử lý relocation
    const ElfW(Phdr) *ro_load = NULL;
    if (!(first_load->p_flags & PF_W))
        ro_load = first_load;
    
    // Xử lý BSS section của segment đầu tiên
    handle_bss(first_load, load_bias, pagesize);

    ElfW(Addr) last_end = first_load->p_vaddr + load_bias +
                          first_load->p_memsz;

    // Map các segment còn lại và bảo vệ các khoảng trống giữa chúng
    for (const ElfW(Phdr) *ph = first_load + 1; ph <= last_load; ++ph){
        if (ph->p_type == PT_LOAD){
            ElfW(Addr) last_page_end = round_up(last_end, pagesize);

            last_end = ph->p_vaddr + load_bias + ph->p_memsz;
            ElfW(Addr) start = round_down(ph->p_vaddr + load_bias, pagesize);
            ElfW(Addr) end = round_up(last_end, pagesize);

            // Bảo vệ khoảng trống giữa các segment (PROT_NONE)
            if (start > last_page_end)
                mprotect((void *)last_page_end,
                        start - last_page_end, PROT_NONE);

            // Map segment hiện tại
            mmap((void *)start, end - start,
                 prot_from_phdr(ph), MAP_PRIVATE | MAP_FIXED, fd, 
                 round_down(ph->p_offset, pagesize));

            // Xử lý BSS cho segment này
            handle_bss(ph, load_bias, pagesize);
            // Cập nhật segment read-only
            if (!(ph->p_flags & PF_W) && !ro_load)
                ro_load = ph;
        }
    }

    // Tìm PT_DYNAMIC header để lấy thông tin
    ElfW(Dyn) *dynamic = NULL;
    for (i = 0; i < ehdr.e_phnum; ++i){
        if (phdr[i].p_type == PT_DYNAMIC){
            assert(dynamic == NULL);    // Chỉ có một PT_DYNAMIC
            dynamic = (ElfW(Dyn) *)(load_bias + phdr[i].p_vaddr);
        }
    }
    assert(dynamic != NULL);
    /*
     * Xử lý relocation entries
     * Đây là các entry cần được điều chỉnh địa chỉ sau khi load
     */
    ElfW(Addr) ro_start = ro_load->p_offset + load_bias;
    ElfW(Addr) ro_end = ro_start + ro_load->p_memsz;

    // Lấy bảng relocation từ dynamic section
    ElfW_Reloc *relocs =
        (ElfW_Reloc *)(load_bias + get_dynamic_entry(dynamic, ELFW_DT_RELW));
    size_t relocs_size = get_dynamic_entry(dynamic, ELFW_DT_RELWSZ);

    // Xử lý từng relocation entry
    for (i = 0; i < relocs_size / sizeof(ElfW_Reloc); i++){
        ElfW_Reloc *reloc = &relocs[i];
        int reloc_type = ELFW_R_TYPE(reloc->r_info);
        switch (reloc_type) {
        case R_X86_64_RELATIVE:
        case R_ARM_RELATIVE:
        case R_AARCH64_RELATIVE:
        {
            // Địa chỉ cần được relocate
            ElfW(Addr) *addr = (ElfW(Addr) *)(load_bias + reloc->r_offset);
            /*
             * Nếu addr nằm trong vùng read-only (.text), ta cần tạm thời
             * cấp quyền WRITE để sửa đổi, sau đó restore lại quyền cũ
             * để tránh vấn đề bảo mật.
             */
            if ((intptr_t) addr < ro_end && (intptr_t) addr >= ro_start) {
                mprotect((void*) round_down((intptr_t) addr, pagesize),
                         pagesize, PROT_WRITE);
                *addr += load_bias; // Điều chỉnh địa chỉ
                mprotect((void*) round_down((intptr_t)addr, pagesize),
                         pagesize, prot_from_phdr(ro_load));
            }
            else
                *addr += load_bias; // Điều chỉnh địa chỉ trực tiếp
            break;
        }
        default:
            assert(0);
        }
    }

    // Tạo object để quản lý ELF đã load
    dloader_p o = malloc(sizeof(struct __DLoader_Internal));
    assert(o != NULL);
    o->load_bias = load_bias;
    o->entry = (void *)(ehdr.e_entry + load_bias);  // Entry point đã điều chỉnh
    o->pt_dynamic = dynamic;
    o->dt_pltgot = NULL;
    o->plt_entries = 0;

    // Lấy thông tin PLT/GOT nếu có
    uintptr_t pltgot = get_dynamic_entry(dynamic, DT_PLTGOT);
    if (pltgot != 0){
        o->dt_pltgot = (void **)(pltgot + load_bias);
        o->dt_jmprel = (ElfW_Reloc *)(get_dynamic_entry(dynamic, DT_JMPREL) +
                                      load_bias);
    }

    close(fd);
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

// Cấu trúc API chính được export
struct __DLoader_API__ DLoader = {
    .load = api_load,
    .get_info = api_get_user_info,
    .set_plt_resolver = api_set_plt_resolver,
    .set_plt_entry = api_set_plt_entry,
};