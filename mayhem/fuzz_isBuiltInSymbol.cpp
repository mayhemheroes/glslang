#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "SymbolTable.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    long long uniqueId = provider.ConsumeIntegral<long long>();
    glslang::TSymbolTable::isBuiltInSymbol(uniqueId);

    return 0;
}