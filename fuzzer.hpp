#pragma once

#include <cstdint>
#include <cstddef>

#define FUZZING

namespace phosphor
{

int FuzzIpmidInitialize(int *argc, char ***argv);

int FuzzIpmid(const uint8_t *Data, size_t Size);

}