// In-process debug stub: breakpoints, single-step, write watchpoints, and
// register/memory access, driven over an inherited pipe by a line protocol.
//
// Every handler enters host segment context before any C++ runs. In guest
// context %gs is 0, and the stack-protector prologue reads %gs:0x14, which
// faults with #GP before the first statement. All I/O is raw syscalls: the
// handler is a coroutine of the controller and must not touch libc.

#include "debug_stub.h"

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

namespace {

constexpr int kMaxBreakpoints = 64;
constexpr int kMaxWatches = 8;
constexpr uint32_t kTrapFlag = 0x100;

struct Breakpoint {
	uintptr_t addr;
	uint8_t saved;
	bool armed;
};
struct Watch {
	uintptr_t addr;
	uintptr_t len;
	uintptr_t page;
	bool active;
};

int g_in = -1, g_out = -1;
unsigned short g_hostFs = 0, g_hostGs = 0;
intptr_t g_delta = 0;
Breakpoint g_bps[kMaxBreakpoints];
Watch g_watches[kMaxWatches];
// Pending single-step purpose after a resume.
enum class Pending { None, RearmBp, WatchStep, UserStep };
Pending g_pending = Pending::None;
int g_pendingBp = -1;
uintptr_t g_pendingFault = 0;
bool g_stepRequested = false;
alignas(16) char g_sigStack[1 << 16];
bool g_enabled = false;

long rawSyscall(long n, long a, long b, long c) {
	long r;
	asm volatile("int $0x80" : "=a"(r) : "a"(n), "b"(a), "c"(b), "d"(c) : "memory");
	return r;
}
void rawWrite(const char *s, size_t n) {
	while (n) {
		long r = rawSyscall(4, g_out, (long)s, (long)n);
		if (r <= 0) return;
		s += r;
		n -= (size_t)r;
	}
}
long rawRead(char *s, size_t n) { return rawSyscall(3, g_in, (long)s, (long)n); }
long rawMprotect(uintptr_t page, int prot) { return rawSyscall(125, (long)page, 4096, prot); }

char *putStr(char *o, const char *s) {
	while (*s) *o++ = *s++;
	return o;
}
char *putHex(char *o, unsigned long v) {
	static const char *d = "0123456789abcdef";
	for (int s = 28; s >= 0; s -= 4) *o++ = d[(v >> s) & 0xf];
	return o;
}
char *putDec(char *o, long v) {
	char tmp[16];
	int n = 0;
	bool neg = v < 0;
	unsigned long u = neg ? (unsigned long)(-v) : (unsigned long)v;
	do { tmp[n++] = '0' + (u % 10); u /= 10; } while (u);
	if (neg) *o++ = '-';
	while (n) *o++ = tmp[--n];
	return o;
}
unsigned long parseHex(const char *&p) {
	unsigned long v = 0;
	while ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
		char c = *p++;
		v = (v << 4) | (unsigned long)(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
	}
	return v;
}
void skipSpace(const char *&p) { while (*p == ' ') ++p; }
bool startsWith(const char *p, const char *w) {
	while (*w) if (*p++ != *w++) return false;
	return true;
}

void sendLine(const char *line) {
	if (g_out < 0) return;
	rawWrite(line, strlen(line));
	rawWrite("\n", 1);
}

// Read one newline-terminated command (blocking, raw).
bool readLine(char *buf, size_t cap) {
	size_t n = 0;
	while (n + 1 < cap) {
		char c;
		long r = rawRead(&c, 1);
		if (r <= 0) return false;
		if (c == '\n') break;
		buf[n++] = c;
	}
	buf[n] = 0;
	return true;
}

int findBp(uintptr_t addr) {
	for (int i = 0; i < kMaxBreakpoints; ++i)
		if (g_bps[i].armed && g_bps[i].addr == addr) return i;
	return -1;
}
bool plant(int i) {
	uintptr_t a = g_bps[i].addr;
	if (rawMprotect(a & ~4095UL, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) return false;
	g_bps[i].saved = *reinterpret_cast<uint8_t *>(a);
	*reinterpret_cast<uint8_t *>(a) = 0xCC;
	return true;
}
void unplant(int i) { *reinterpret_cast<uint8_t *>(g_bps[i].addr) = g_bps[i].saved; }

int findWatchPage(uintptr_t addr) {
	for (int i = 0; i < kMaxWatches; ++i)
		if (g_watches[i].active && (addr & ~4095UL) == g_watches[i].page) return i;
	return -1;
}
void protectWatch(int i) { rawMprotect(g_watches[i].page, PROT_READ); }
void openWatch(int i) { rawMprotect(g_watches[i].page, PROT_READ | PROT_WRITE); }

void sendRegs(gregset_t &gr) {
	char buf[256];
	char *o = putStr(buf, "regs eax=");
	o = putHex(o, gr[REG_EAX]); o = putStr(o, " ebx="); o = putHex(o, gr[REG_EBX]);
	o = putStr(o, " ecx="); o = putHex(o, gr[REG_ECX]); o = putStr(o, " edx="); o = putHex(o, gr[REG_EDX]);
	o = putStr(o, " esi="); o = putHex(o, gr[REG_ESI]); o = putStr(o, " edi="); o = putHex(o, gr[REG_EDI]);
	o = putStr(o, " ebp="); o = putHex(o, gr[REG_EBP]); o = putStr(o, " esp="); o = putHex(o, gr[REG_ESP]);
	o = putStr(o, " eip="); o = putHex(o, gr[REG_EIP]); o = putStr(o, " efl="); o = putHex(o, gr[REG_EFL]);
	*o = 0;
	sendLine(buf);
}

// Serve controller commands until a resume verb. Returns true for step.
bool serve(gregset_t &gr) {
	char line[512];
	for (;;) {
		if (!readLine(line, sizeof line)) {
			// The controller is gone. Detach: remove our breakpoints and
			// watches and let the guest finish on its own.
			for (int i = 0; i < kMaxBreakpoints; ++i) if (g_bps[i].armed) { unplant(i); g_bps[i].armed = false; }
			for (int i = 0; i < kMaxWatches; ++i) if (g_watches[i].active) { openWatch(i); g_watches[i].active = false; }
			g_enabled = false;
			return false;
		}
		const char *p = line;
		if (startsWith(p, "go")) return false;
		if (startsWith(p, "step")) return true;
		if (startsWith(p, "kill")) rawSyscall(252, 0xDE, 0, 0);
		if (startsWith(p, "regs")) { sendRegs(gr); continue; }
		if (startsWith(p, "bp ")) {
			p += 3; skipSpace(p);
			uintptr_t a = (uintptr_t)parseHex(p) + (uintptr_t)g_delta;
			int slot = -1;
			for (int i = 0; i < kMaxBreakpoints; ++i) if (!g_bps[i].armed) { slot = i; break; }
			if (slot < 0 || findBp(a) >= 0) { sendLine("err bp"); continue; }
			g_bps[slot].addr = a; g_bps[slot].armed = true;
			if (!plant(slot)) { g_bps[slot].armed = false; sendLine("err plant"); continue; }
			sendLine("ok");
			continue;
		}
		if (startsWith(p, "watch ")) {
			p += 6; skipSpace(p);
			uintptr_t a = (uintptr_t)parseHex(p) + (uintptr_t)g_delta;
			skipSpace(p);
			uintptr_t len = (uintptr_t)parseHex(p);
			int slot = -1;
			for (int i = 0; i < kMaxWatches; ++i) if (!g_watches[i].active) { slot = i; break; }
			if (slot < 0) { sendLine("err watch"); continue; }
			g_watches[slot] = {a, len ? len : 1, a & ~4095UL, true};
			protectWatch(slot);
			sendLine("ok");
			continue;
		}
		if (startsWith(p, "read ")) {
			p += 5; skipSpace(p);
			uintptr_t a = (uintptr_t)parseHex(p) + (uintptr_t)g_delta;
			skipSpace(p);
			unsigned long len = parseHex(p);
			if (len > 200) len = 200;
			char buf[512];
			char *o = putStr(buf, "mem ");
			// A read of unmapped memory would fault inside the handler; the
			// controller only reads addresses the guest has published.
			for (unsigned long i = 0; i < len; ++i) {
				uint8_t b = *reinterpret_cast<uint8_t *>(a + i);
				// A planted breakpoint is the stub's, not the guest's: show the
				// original byte, as any debugger does.
				int planted = findBp(a + i);
				if (planted >= 0) b = g_bps[planted].saved;
				*o++ = "0123456789abcdef"[b >> 4]; *o++ = "0123456789abcdef"[b & 15];
			}
			*o = 0;
			sendLine(buf);
			continue;
		}
		if (startsWith(p, "setreg ")) {
			p += 7; skipSpace(p);
			const char *name = p;
			while (*p && *p != ' ') ++p;
			size_t nl = (size_t)(p - name);
			skipSpace(p);
			unsigned long v = parseHex(p);
			int reg = -1;
			if (nl == 3) {
				if (!strncmp(name, "eax", 3)) reg = REG_EAX; else if (!strncmp(name, "ebx", 3)) reg = REG_EBX;
				else if (!strncmp(name, "ecx", 3)) reg = REG_ECX; else if (!strncmp(name, "edx", 3)) reg = REG_EDX;
				else if (!strncmp(name, "esi", 3)) reg = REG_ESI; else if (!strncmp(name, "edi", 3)) reg = REG_EDI;
				else if (!strncmp(name, "ebp", 3)) reg = REG_EBP; else if (!strncmp(name, "esp", 3)) reg = REG_ESP;
				else if (!strncmp(name, "eip", 3)) reg = REG_EIP;
			}
			if (reg < 0) { sendLine("err reg"); continue; }
			gr[reg] = (greg_t)v;
			sendLine("ok");
			continue;
		}
		sendLine("err cmd");
	}
}

void resumeAfter(gregset_t &gr, bool step, Pending why, int bp, uintptr_t fault) {
	g_pending = why;
	g_pendingBp = bp;
	g_pendingFault = fault;
	g_stepRequested = step;
	if (why != Pending::None || step) gr[REG_EFL] |= kTrapFlag;
}

__attribute__((optimize("no-stack-protector"))) void onTrap(int, siginfo_t *, void *ctx) {
	asm volatile("mov %0, %%fs" : : "r"(g_hostFs));
	asm volatile("mov %0, %%gs" : : "r"(g_hostGs));
	auto &gr = static_cast<ucontext_t *>(ctx)->uc_mcontext.gregs;
	uintptr_t eip = (uintptr_t)gr[REG_EIP];
	// Single-step completion: TF trap lands with eip at the next instruction.
	if (g_pending != Pending::None || g_stepRequested) {
		gr[REG_EFL] &= ~kTrapFlag;
		Pending why = g_pending;
		g_pending = Pending::None;
		if (why == Pending::RearmBp && g_pendingBp >= 0 && g_bps[g_pendingBp].armed) plant(g_pendingBp);
		if (why == Pending::WatchStep) {
			int w = findWatchPage(g_pendingFault);
			if (w >= 0) protectWatch(w);
			bool inside = false;
			for (int i = 0; i < kMaxWatches; ++i)
				if (g_watches[i].active && g_pendingFault >= g_watches[i].addr &&
					g_pendingFault < g_watches[i].addr + g_watches[i].len) inside = true;
			if (inside) {
				char buf[96];
				char *o = putStr(buf, "stop watch addr=");
				o = putHex(o, g_pendingFault - (uintptr_t)g_delta);
				o = putStr(o, " eip="); o = putHex(o, eip - (uintptr_t)g_delta); *o = 0;
				sendLine(buf);
				bool step = serve(gr);
				resumeAfter(gr, step, Pending::None, -1, 0);
				return;
			}
		}
		if (g_stepRequested) {
			g_stepRequested = false;
			char buf[64];
			char *o = putStr(buf, "stop step eip="); o = putHex(o, eip - (uintptr_t)g_delta); *o = 0;
			sendLine(buf);
			bool step = serve(gr);
			resumeAfter(gr, step, Pending::None, -1, 0);
		}
		return;
	}
	// Breakpoint hit: int3 leaves eip one past the instruction.
	int bp = findBp(eip - 1);
	if (bp < 0) return; // not ours; leave the guest's own int3 semantics alone
	eip -= 1;
	gr[REG_EIP] = (greg_t)eip;
	unplant(bp);
	char buf[64];
	char *o = putStr(buf, "stop bp eip="); o = putHex(o, eip - (uintptr_t)g_delta); *o = 0;
	sendLine(buf);
	bool step = serve(gr);
	// Execute the original instruction, then re-plant.
	resumeAfter(gr, step, g_bps[bp].armed ? Pending::RearmBp : Pending::None, bp, 0);
}

__attribute__((optimize("no-stack-protector"))) void onSegv(int, siginfo_t *si, void *ctx) {
	asm volatile("mov %0, %%fs" : : "r"(g_hostFs));
	asm volatile("mov %0, %%gs" : : "r"(g_hostGs));
	auto &gr = static_cast<ucontext_t *>(ctx)->uc_mcontext.gregs;
	uintptr_t fault = (uintptr_t)si->si_addr;
	int w = findWatchPage(fault);
	if (w < 0) {
		// A genuine guest fault. Report it and let the default action follow.
		char buf[96];
		char *o = putStr(buf, "fault addr="); o = putHex(o, fault);
		o = putStr(o, " eip="); o = putHex(o, (uintptr_t)gr[REG_EIP] - (uintptr_t)g_delta); *o = 0;
		sendLine(buf);
		signal(SIGSEGV, SIG_DFL);
		return;
	}
	// Let the write through under single-step, then re-protect and decide.
	openWatch(w);
	resumeAfter(gr, false, Pending::WatchStep, -1, fault);
}

} // namespace

namespace wibo::debugstub {

void install(intptr_t relocationDelta, const char *imageName, uintptr_t imageBase) {
	const char *in = std::getenv("WIBO_DEBUG_IN");
	const char *out = std::getenv("WIBO_DEBUG_OUT");
	if (!in || !out) return;
	g_in = atoi(in);
	g_out = atoi(out);
	g_delta = relocationDelta;
	asm volatile("mov %%fs, %0" : "=r"(g_hostFs));
	asm volatile("mov %%gs, %0" : "=r"(g_hostGs));
	stack_t ss {};
	ss.ss_sp = g_sigStack;
	ss.ss_size = sizeof g_sigStack;
	sigaltstack(&ss, nullptr);
	struct sigaction trap {};
	trap.sa_sigaction = onTrap;
	trap.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
	sigaction(SIGTRAP, &trap, nullptr);
	struct sigaction segv {};
	segv.sa_sigaction = onSegv;
	segv.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
	sigaction(SIGSEGV, &segv, nullptr);
	g_enabled = true;
	char buf[512];
	char *o = putStr(buf, "hello pid="); o = putDec(o, getpid());
	o = putStr(o, " image="); o = putStr(o, imageName ? imageName : "?");
	o = putStr(o, " base="); o = putHex(o, imageBase);
	o = putStr(o, " delta="); o = putHex(o, (unsigned long)relocationDelta); *o = 0;
	sendLine(buf);
	// The controller sets breakpoints and watches before the guest starts.
	ucontext_t scratch {};
	serve(scratch.uc_mcontext.gregs);
}

// Keep arguments live and calls visible in optimized builds. These hooks do
// not allocate, inspect the environment, or change guest state.
__attribute__((noinline, used))
void moduleMapped(const char *path, uintptr_t base, uintptr_t size) {
	asm volatile("" : : "r"(path), "r"(base), "r"(size) : "memory");
}

__attribute__((noinline, used))
void moduleUnmapped(uintptr_t base) {
	asm volatile("" : : "r"(base) : "memory");
}

void reportExit(int code) {
	if (!g_enabled) return;
	char buf[64];
	char *o = putStr(buf, "exit code="); o = putDec(o, code);
	o = putStr(o, " pid="); o = putDec(o, getpid()); *o = 0;
	sendLine(buf);
}

} // namespace wibo::debugstub
