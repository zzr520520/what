// WatusiShield.m — Crash Shield dylib
// 拦截 objc_exception_throw，吞掉由 libWatusiToolsSL 引发的 NSException，防止进程 abort。
// Hook 引擎优先级：CydiaSubstrate MSHookFunction -> libhooker(MSHookFunction 兼容) -> libellekit -> libsubstrate。
// 无 Hook 引擎时退化为全局未捕获异常日志（尽力而为）。

#import <Foundation/Foundation.h>
#import <dlfcn.h>

typedef int (*MSHookFuncPtr)(void *symbol, void *replace, void **result);

static void (*orig_objc_exception_throw)(id exception) = NULL;
static MSHookFuncPtr ac_hookFunc = NULL;

#pragma mark - 命中过滤：调用栈来自 Watusi 则吞掉

static BOOL ACStackFromWatusi(void) {
    @try {
        NSArray *syms = [NSThread callStackSymbols];
        if (syms.count == 0) return NO;
        for (NSString *s in syms) {
            if (s.length == 0) continue;
            if ([s containsString:@"libWatusiToolsSL"] || [s containsString:@"Watusi"] || [s containsString:@"watusi"]) return YES;
        }
    } @catch (NSException *e) {}
    return NO;
}

#pragma mark - 替换函数

static void AC_fake_exception_throw(id exception) {
    @try {
        if ([exception isKindOfClass:[NSException class]]) {
            if (ACStackFromWatusi()) {
                NSLog(@"[WatusiShield] 🛡️ 已拦截 Watusi 异常: %@ | 原因: %@", [(NSException *)exception name], [(NSException *)exception reason]);
                return; // 吞掉异常，不走 abort
            }
        }
    } @catch (NSException *inner) {}
    if (orig_objc_exception_throw) orig_objc_exception_throw(exception);
}

#pragma mark - 全局未捕获异常兜底（仅日志）

static void AC_uncaught_handler(NSException *exception) {
    NSLog(@"[WatusiShield] 未捕获异常: %@ | 原因: %@\n%@", exception.name, exception.reason, [exception callStackSymbols]);
}

#pragma mark - Hook 引擎探测

static MSHookFuncPtr ACResolveHookEngine(void) {
    // 1) 已加载的 Substrate/Hooker 兼容层（RTLD_DEFAULT 直接找）
    MSHookFuncPtr f = (MSHookFuncPtr)dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (f) return f;
    // 2) 常见越狱 Hook 引擎路径
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
        if (f) {
            NSLog(@"[WatusiShield] Hook 引擎: %s", candidates[i]);
            return f;
        }
    }
    return NULL;
}

#pragma mark - 入口

__attribute__((constructor))
static void WatusiShieldInit(void) {
    @autoreleasepool {
        NSLog(@"[WatusiShield] 补丁加载，开始挂载异常防护...");
        NSSetUncaughtExceptionHandler(&AC_uncaught_handler);

        // objc_exception_throw 位于 libobjc.A.dylib（Foundation 加载后必然已映射）
        void *sym = dlsym(RTLD_DEFAULT, "objc_exception_throw");
        if (!sym) {
            void *libobjc = dlopen("/usr/lib/libobjc.A.dylib", RTLD_NOW);
            if (libobjc) sym = dlsym(libobjc, "objc_exception_throw");
        }
        if (!sym) {
            NSLog(@"[WatusiShield] ❌ 未找到 objc_exception_throw，防护未挂载");
            return;
        }

        ac_hookFunc = ACResolveHookEngine();
        if (ac_hookFunc) {
            int rc = ac_hookFunc(sym, (void *)AC_fake_exception_throw, (void **)&orig_objc_exception_throw);
            if (rc == 0 && orig_objc_exception_throw) {
                NSLog(@"[WatusiShield] ✅ objc_exception_throw inline hook 挂载成功 (MSHookFunction)");
            } else {
                NSLog(@"[WatusiShield] ❌ hook 返回 %d，防护未挂载", rc);
            }
        } else {
            NSLog(@"[WatusiShield] ⚠️ 未找到任何 Hook 引擎(MSHookFunction)，仅保留未捕获异常日志");
        }
    }
}
