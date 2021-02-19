//
// Created by Allison Husain on 1/12/21.
//

#ifndef HONGGFUZZ_HONEYBEE_H
#define HONGGFUZZ_HONEYBEE_H
#include "honggfuzz.h"

bool arch_honeybeeInit(honggfuzz_t* hfuzz);

bool arch_honeybeeOpen(run_t* run);

bool arch_honeybeeClose(run_t* run);

void arch_honeybeeAnalyze(run_t* run);

#endif //HONGGFUZZ_HONEYBEE_H
