I do not have much time to explain this. I am just putting all my best repos on Git so people can Ctrl+C me.

So I will give a simple setup guide:

1. Run the `.bat` script.
2. Get the `.sys` signed, or just use a manual mapper like `kdmapper`.
3. Run it.

Here is an example below showing how to comm with the hypervisor.

### How to get the bootstrap magic

```cpp
uint64_t HvBootstrap() {
    uint32_t b = *(volatile uint32_t*)(0x7FFE02C4);
    uint64_t m = (0x46475248ULL ^ ((uint64_t)(b) * 0x5DEECE66DULL + 0xBULL));
    if (m == 0 || m == 0x464F5247ULL)
        m ^= 0xDEADCAFEULL;
    return m;
}
```

### How to make a raw call

```cpp
uint64_t HvOnce(uint64_t m, uint64_t c, uint64_t a1, uint64_t a2, uint64_t a3) {
    __try {
        return HvCpuidCallRaw(m, c, a1, a2, a3);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}
```

### How to make an auto magic fix

```cpp
uint64_t HvCall(uint64_t c, uint64_t a1, uint64_t a2, uint64_t a3) {
    uint64_t r = HvOnce(g_HvMagic, c, a1, a2, a3);
    if (r != 0)
        return r;
    uint64_t p = HvOnce(HvBootstrap(), 0x01, 0, 0, 0);
    if (p == 0 || p == 0x00000000)
        return 0;
    if (p != 0x00000001)
        g_HvMagic = p;
    return HvOnce(g_HvMagic, c, a1, a2, a3);
}
```

### How to connect

```cpp
bool HvConnect(uint32_t pid) {
    g_HvMagic = HvBootstrap();
    uint64_t p = HvOnce(g_HvMagic, 0x01, 0, 0, 0);
    if (p == 0)
        return false;
    if (p != 0x00000001)
        g_HvMagic = p;
    return HvCall(0x10, pid, 0, 0) == 0x00000001;
}
```

### How to read & write to memory

```cpp
// read
bool HvRead(uint64_t addr, void* buf, uint32_t size) {
    if (addr < 0x10000)
        return false;
    return HvCall(0x11, addr, (uint64_t)buf, size) == 0x00000001;
}

// write
bool HvWrite(uint64_t addr, void* buf, uint32_t size) {
    if (addr < 0x10000)
        return false;
    return HvCall(0x12, addr, (uint64_t)buf, size) == 0x00000001;
}
```
