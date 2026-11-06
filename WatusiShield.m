// WatusiShield.m — Watusi 崩溃防护 dylib v2
// 1) fishhook 改绑 libWatusiToolsSL 镜像 GOT 中的 _userInfoForFileAndLine（主路径，无需 Hook 引擎/无需越狱写权限）
// 2) MSHookFunction 拦截 objc_exception_throw（有 Substrate/Hooker/ElleKit 的环境生效，吞 Watusi 异常）
// 3) 兜底：vm_protect + RET 补丁 Foundation 的 _userInfoForFileAndLine（需越狱内核可写共享缓存）

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <sys/icache.h>
#import <string.h>
#import <stdlib.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define AC_LC_SEGMENT LC_SEGMENT_64

#ifndef INDIRECT_SYMBOL_LOCAL
#define INDIRECT_SYMBOL_LOCAL 0x80000000u
#endif
#ifndef INDIRECT_SYMBOL_ABS
#define INDIRECT_SYMBOL_ABS 0x40000000u
#endif

#pragma mark - fishhook（内联实现，针对单镜像改绑）

struct AC_rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

struct AC_rebindings_entry {
    struct AC_rebinding *rebindings;
    size_t nel;
    struct AC_rebindings_entry *next;
};

static struct AC_rebindings_entry *_AC_rebindings_head = NULL;

static int AC_prepend_rebindings(struct AC_rebindings_entry **head,
                                 const struct AC_rebinding rebindings[], size_t nel) {
    struct AC_rebindings_entry *newEntry = (struct AC_rebindings_entry *)malloc(sizeof(struct AC_rebindings_entry));
    if (!newEntry) return -1;
    newEntry->rebindings = (struct AC_rebinding *)malloc(sizeof(struct AC_rebinding) * nel);
    if (!newEntry->rebindings) { free(newEntry); return -1; }
    memcpy(newEntry->rebindings, rebindings, sizeof(struct AC_rebinding) * nel);
    newEntry->nel = nel;
    newEntry->next = *head;
    *head = newEntry;
    return 0;
}

static void AC_make_page_writable(void *addr, size_t len) {
    vm_address_t page = (vm_address_t)addr & ~(vm_address_t)(PAGE_SIZE - 1);
    vm_protect(mach_task_self(), page, len + PAGE_SIZE, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
}

static void AC_perform_rebinding_with_section(struct AC_rebindings_entry *rebindings,
                                              section_t *section,
                                              intptr_t slide,
                                              nlist_t *symtab,
                                              char *strtab,
                                              uint32_t *indirect_symtab) {
    uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
    void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
    size_t entries = section->size / sizeof(void *);
    for (size_t i = 0; i < entries; i++) {
        uint32_t symtabIndex = indirect_symbol_indices[i];
        if (symtabIndex == INDIRECT_SYMBOL_ABS ||
            symtabIndex == INDIRECT_SYMBOL_LOCAL ||
            symtabIndex == (INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL)) continue;
        uint32_t strtabOffset = symtab[symtabIndex].n_un.n_strx;
        if (strtabOffset == 0) continue;
        char *symName = strtab + strtabOffset;
        if (!symName || symName[0] != '_') continue;
        struct AC_rebindings_entry *cur = rebindings;
        while (cur) {
            int matched = 0;
            for (size_t k = 0; k < cur->nel; k++) {
                if (strcmp(symName, cur->rebindings[k].name) == 0) {
                    if (cur->rebindings[k].replaced && indirect_symbol_bindings[i] != cur->rebindings[k].replacement) {
                        *(cur->rebindings[k].replaced) = indirect_symbol_bindings[i];
                    }
                    indirect_symbol_bindings[i] = cur->rebindings[k].replacement;
                    matched = 1;
                    break;
                }
            }
            (void)matched;
            cur = cur->next;
        }
    }
}

static void AC_rebind_symbols_for_image(struct AC_rebindings_entry *rebindings,
                                        const struct mach_header *header,
                                        intptr_t slide) {
    segment_command_t *curSegCmd = NULL;
    segment_command_t *linkeditSegment = NULL;
    struct symtab_command *symtabCmd = NULL;
    struct dysymtab_command *dysymtabCmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++, cur += curSegCmd->cmdsize) {
        curSegCmd = (segment_command_t *)cur;
        if (curSegCmd->cmd == AC_LC_SEGMENT) {
            if (strcmp(curSegCmd->segname, SEG_LINKEDIT) == 0) linkeditSegment = curSegCmd;
        } else if (curSegCmd->cmd == LC_SYMTAB) {
            symtabCmd = (struct symtab_command *)curSegCmd;
        } else if (curSegCmd->cmd == LC_DYSYMTAB) {
            dysymtabCmd = (struct dysymtab_command *)curSegCmd;
        }
    }
    if (!symtabCmd || !linkeditSegment || !dysymtabCmd) return;

    uintptr_t linkeditBase = (uintptr_t)slide + linkeditSegment->vmaddr - linkeditSegment->fileoff;
    nlist_t *symtab = (nlist_t *)(linkeditBase + symtabCmd->symoff);
    char *strtab = (char *)(linkeditBase + symtabCmd->stroff);
    uint32_t *indirectSymtab = (uint32_t *)(linkeditBase + dysymtabCmd->indirectsymoff);

    cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++, cur += curSegCmd->cmdsize) {
        curSegCmd = (segment_command_t *)cur;
        if (curSegCmd->cmd != AC_LC_SEGMENT) continue;
        if (strcmp(curSegCmd->segname, SEG_DATA) != 0 &&
            strcmp(curSegCmd->segname, "__DATA_CONST") != 0 &&
            strcmp(curSegCmd->segname, "__AUTH_CONST") != 0) continue;
        uintptr_t base = (uintptr_t)cur + sizeof(segment_command_t);
        for (uint32_t j = 0; j < curSegCmd->nsects; j++) {
            section_t *sect = (section_t *)base;
            base += sizeof(section_t);
            uint8_t type = sect->flags & SECTION_TYPE;
            if (type == S_NON_LAZY_SYMBOL_POINTERS || type == S_LAZY_SYMBOL_POINTERS) {
                AC_make_page_writable((void *)((uintptr_t)slide + sect->addr), sect->size);
                AC_perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirectSymtab);
            }
        }
    }
}

// 在指定镜像内改绑符号；成功（改到原指针）返回 YES
static BOOL AC_rebind_in_image(const char *imageNamePart,
                               const char *symbolName,
                               void *replacement,
                               void **replacedOut) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || !strstr(name, imageNamePart)) continue;

        const struct mach_header *hdr = _dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);

        // 链式修复(chained fixups)镜像不适用经典改绑，避免误写
        BOOL hasChainedFixups = NO;
        uintptr_t cur = (uintptr_t)hdr + sizeof(mach_header_t);
        segment_command_t *cmd = NULL;
        for (uint32_t c = 0; c < hdr->ncmds; c++, cur += cmd->cmdsize) {
            cmd = (segment_command_t *)cur;
            if (cmd->cmd == LC_DYLD_CHAINED_FIXUPS) { hasChainedFixups = YES; break; }
        }
        if (hasChainedFixups) {
            NSLog(@"[WatusiShield] ⚠️ %@ 使用 chained fixups，跳过 GOT 改绑，走兜底补丁", imageNamePart);
            return NO;
        }

        if (*replacedOut) *replacedOut = NULL;
        struct AC_rebinding r = { symbolName, replacement, replacedOut };
        if (AC_prepend_rebindings(&_AC_rebindings_head, &r, 1) != 0) return NO;
        AC_rebind_symbols_for_image(_AC_rebindings_head, hdr, slide);
        if (*replacedOut) {
            NSLog(@"[WatusiShield] ✅ 已在 %@ 内改绑 %s (原地址: %p)", imageNamePart, symbolName, *replacedOut);
            return YES;
        }
        return NO;
    }
    NSLog(@"[WatusiShield] ⚠️ 未找到镜像 %@", imageNamePart);
    return NO;
}

#pragma mark - 假函数

static id (*orig_userInfoForFileAndLine)(id, ...) = NULL;

static id AC_fake_userInfoForFileAndLine(id a0, ...) {
    return nil; // 返回空，避开系统内部指针解引用 / PAC 敏感路径
}

static void (*orig_objc_exception_throw)(id exception) = NULL;
typedef int (*MSHookFuncPtr)(void *symbol, void *replace, void **result);
static MSHookFuncPtr ac_hookFunc = NULL;

static void AC_fake_exception_throw(id exception) {
    @try {
        if ([exception isKindOfClass:[NSException class]]) {
            NSArray *syms = [NSThread callStackSymbols];
            for (NSString *s in syms) {
                if ([s containsString:@"libWatusiToolsSL"] || [s containsString:@"Watusi"]) {
                    NSLog(@"[WatusiShield] 🛡️ 已拦截 Watusi 异常: %@ | 原因: %@",
                          [(NSException *)exception name], [(NSException *)exception reason]);
                    return;
                }
            }
        }
    } @catch (NSException *inner) {}
    if (orig_objc_exception_throw) orig_objc_exception_throw(exception);
}

#pragma mark - Hook 引擎探测

static MSHookFuncPtr ACResolveHookEngine(void) {
    MSHookFuncPtr f = (MSHookFuncPtr)dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (f) return f;
    const char *candidates[] = {
        "/usr/lib/ellekit/ellekit.dylib",
        "/usr/lib/libellekit.dylib",
        "/usr/lib/libhooker.dylib",
        "/usr/lib/libsubstrate.dylib",
        "/usr/lib/substrate/libsubstrate.dylib",
        "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
    };
    for (unsigned long i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        void *h = dlopen(candidates[i], RTLD_NOW | RTLD_GLOBAL);
        if (!h) continue;
        f = (MSHookFuncPtr)dlsym(h, "MSHookFunction");
        if (f) return f;
    }
    return NULL;
}

#pragma mark - 兜底：vm_protect + RET 补丁

static BOOL AC_patch_ret(uintptr_t target) {
    if (!target) return NO;
    vm_address_t pageStart = target & ~(vm_address_t)(PAGE_SIZE - 1);
    kern_return_t kr = vm_protect(mach_task_self(), pageStart, PAGE_SIZE, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[WatusiShield] ❌ vm_protect 失败 (%d)：共享缓存不可写（无越狱内核权限）", kr);
        return NO;
    }
    *(uint32_t *)target = 0xD65F03C0; // RET
    sys_icache_invalidate((void *)target, 4);
    vm_protect(mach_task_self(), pageStart, PAGE_SIZE, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    NSLog(@"[WatusiShield] ✅ 已将 %p 首条指令改为 RET (兜底补丁)", (void *)target);
    return YES;
}

#pragma mark - 入口

__attribute__((constructor(101)))
static void WatusiShieldInit(void) {
    @autoreleasepool {
        NSLog(@"[WatusiShield] v2 补丁加载 (fishhook GOT 改绑 + 异常拦截 + RET 兜底)");

        // —— 主路径：fishhook 改绑 libWatusiToolsSL 镜像内的 _userInfoForFileAndLine ——
        BOOL rebound = AC_rebind_in_image("libWatusiToolsSL", "_userInfoForFileAndLine",
                                          (void *)AC_fake_userInfoForFileAndLine,
                                          (void **)&orig_userInfoForFileAndLine);
        if (rebound) {
            NSLog(@"[WatusiShield] 🎯 PAC 崩溃点已通过 GOT 改绑屏蔽（无需 Hook 引擎）");
        } else {
            // —— 兜底：dlsym / 硬编码偏移 + RET 补丁 ——
            NSLog(@"[WatusiShield] GOT 改绑未成功，尝试 RET 兜底补丁...");
            void *sym = dlsym(RTLD_DEFAULT, "_userInfoForFileAndLine");
            if (sym) {
#if __has_feature(ptrauth_calls)
                sym = ptrauth_strip(sym, ptrauth_key_function_pointer);
#endif
                AC_patch_ret((uintptr_t)sym);
            } else {
                // 崩溃报告给出的 Foundation 内偏移（iOS 17.2.1：imageOffset 7015896 = 0x6B0DD8）
                uint32_t count = _dyld_image_count();
                BOOL patched = NO;
                for (uint32_t i = 0; i < count; i++) {
                    const char *name = _dyld_get_image_name(i);
                    if (name && strstr(name, "Foundation.framework/Foundation")) {
                        uintptr_t addr = (uintptr_t)_dyld_get_image_header(i) + 7015896;
                        NSLog(@"[WatusiShield] ⚠️ 符号未导出，按 iOS 17.2.1 偏移 0x6B0DD8 修补 (其它系统版本可能不准)");
                        patched = AC_patch_ret(addr);
                        break;
                    }
                }
                if (!patched) NSLog(@"[WatusiShield] ❌ RET 兜底也未完成，请回报日志");
            }
        }

        // —— 附加：Hook objc_exception_throw（有 Hook 引擎的环境才生效）——
        void *throwSym = dlsym(RTLD_DEFAULT, "objc_exception_throw");
        if (throwSym) {
            ac_hookFunc = ACResolveHookEngine();
            if (ac_hookFunc) {
                int rc = ac_hookFunc(throwSym, (void *)AC_fake_exception_throw, (void **)&orig_objc_exception_throw);
                if (rc == 0 && orig_objc_exception_throw) {
                    NSLog(@"[WatusiShield] ✅ objc_exception_throw hook 挂载成功");
                }
            } else {
                NSLog(@"[WatusiShield] （无 Hook 引擎，异常拦截层跳过——不影响 GOT 改绑主路径）");
            }
        }
    }
}
