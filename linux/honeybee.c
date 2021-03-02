//
// Created by Allison Husain on 1/12/21.
//

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "libhfcommon/common.h"
#include "libhfcommon/log.h"
#include "libhfcommon/util.h"

#include "honeybee.h"
#include "/home/allison/Desktop/Honeybee/honey_analyzer/honey_analyzer.h"

typedef struct {
    ha_capture_session_t capture_session;
    ha_session_t analysis_session;
} honeybee_tracer;

struct {
    hb_hive *global_hive;
} honeybee_global;

void pin_process_to_cpu(pid_t pid, int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    if (sched_setaffinity(pid, sizeof mask, &mask)) {
        perror("Couldn't pin to CPU");
    }
}

bool arch_honeybeeInit(honggfuzz_t* hfuzz HF_ATTR_UNUSED) {
    /* this is called once */
    if (!(hfuzz->feedback.dynFileMethod & _HF_DYNFILE_IPT_EDGE)) {
        return true;
    }

    const char *hive_path = hfuzz->honeybee_config.hive_path;
    if (!hive_path) {
        LOG_F("No hive path provided!");
    }

    //Init the global hive file
    if (!honeybee_global.global_hive) {
        if (!(honeybee_global.global_hive = hb_hive_alloc(hive_path))) {
            LOG_F("Unable to load hive file! %s", hive_path);
        }
    }

    //Configure global buffers
    ha_capture_session_t temp_capture_session = NULL;
    if (ha_capture_session_alloc(&temp_capture_session, 0) < 0) {
        LOG_F("Failed to open honeybee capture session. Is the kernel module loaded and do you have appropriate "
              "permissions to access it?");
    }

//    //Disable tracing on this core in case we're recovering
//    ha_capture_session_set_trace_enable(temp_capture_session, 0x00);

    //52MB
    if (ha_capture_session_set_global_buffer_size(temp_capture_session, 400, 5) < 0) {
        LOG_F("Could not set global buffer size. This is not an allocation error but the driver refused to accept the "
              "the change.\n");
    }

    ha_capture_session_free(temp_capture_session);

    return true;
}

bool arch_honeybeeOpen(run_t* run) {
    if (!(run->global->feedback.dynFileMethod & _HF_DYNFILE_IPT_EDGE)) {
        return true;
    }

    int result;

    //This is called once per process. This is true for persistent fuzzers too.
//    LOG_E("run id = %d\n", run->fuzzNo);

    honeybee_tracer *tracer = run->arch_linux.honeybeeTracer;

    if (!tracer) {
        tracer = calloc(1, sizeof(honeybee_tracer));
        if (!tracer) {
            LOG_F("Could not allocate honeybee internal structure (out of memory)\n");
        }

        //FIXME: Do something semi-intelligent for CPU binding. fuzzNo is zero indexed and by default we use half the
        // cores and so multiplying by two skips SMP cores LOL
        uint16_t cpu = 2 * run->fuzzNo;

        //We need to pin the process to the CPU we're tracing otherwise we won't capture it
        pin_process_to_cpu(run->pid, cpu);

        if ((result = ha_capture_session_alloc(&tracer->capture_session, cpu)) < 0) {
            LOG_F("Failed to open honeybee capture session. Is the kernel module loaded and do you have appropriate "
                  "permissions to access it? Error=%d\n", result);
        }

        if ((result = ha_session_alloc(&tracer->analysis_session, honeybee_global.global_hive)) < 0) {
            LOG_F("Could not allocate analysis session. This is likely an out of memory error. Error=%d\n", result);
        }
        run->arch_linux.honeybeeTracer = tracer;
    }

    ha_capture_session_range_filter filters[4];
    bzero(&filters, sizeof(ha_capture_session_range_filter) * 4);

    uint64_t hive_filter_start = run->global->honeybee_config.range_start;
    uint64_t hive_filter_stop = run->global->honeybee_config.range_stop;
    if (hive_filter_start < hive_filter_stop) {
        filters[0].start = hive_filter_start;
        filters[0].stop = hive_filter_stop;
        filters[0].enabled = 0x1;
    } else {
        LOG_F("Hive had invalid VIP range: %p -> %p", (void *)hive_filter_start, (void *)hive_filter_stop);
    }

    if ((result = ha_capture_session_configure_tracing(tracer->capture_session, run->pid, filters)) < 0) {
        LOG_F("Could not configure tracing on cpu=%d, error=%d\n", run->fuzzNo, result);
    }

    if ((result = ha_capture_session_set_trace_enable(tracer->capture_session, 0x1, 0x1)) < 0) {
        LOG_F("Could not start tracing on cpu=%d, error=%d\n", run->fuzzNo, result);
    }

    return true;
}

bool arch_honeybeeClose(run_t* run) {
    if (!(run->global->feedback.dynFileMethod & _HF_DYNFILE_IPT_EDGE)) {
        return true;
    }

    honeybee_tracer *tracer = run->arch_linux.honeybeeTracer;
    if (!tracer) {
        return true;
    }

    //disable tracing. This should already be done after analysis via reap but just for safety?
    ha_capture_session_set_trace_enable(tracer->capture_session, 0x0, 0x1);

    return true;
}

__attribute__((hot))
static void process_block(ha_session_t session HF_ATTR_UNUSED, void *context, uint64_t ip) {
    run_t* run = context;
    ip &= _HF_PERF_BITMAP_BITSZ_MASK;

    register bool prev = ATOMIC_BITMAP_SET(run->global->feedback.covFeedbackMap->bbMapPc, ip);
    if (!prev) {
        run->hwCnts.newBBCnt++;
    }
}

void arch_honeybeeAnalyze(run_t* run) {
    /* this is called on each iteration */

    if (!(run->global->feedback.dynFileMethod & _HF_DYNFILE_IPT_EDGE)) {
        return;
    }

    honeybee_tracer *tracer = run->arch_linux.honeybeeTracer;
    if (!tracer) {
        return;
    }

    int result;

    //Suspend tracing while we analyze
    if ((result = ha_capture_session_set_trace_enable(tracer->capture_session, 0x0, 0x0)) < 0) {
        LOG_F("Could not start tracing on cpu=%d, error=%d\n", run->fuzzNo, result);
    }

    uint8_t *trace_buffer;
    uint64_t trace_length;
    if ((result = ha_capture_get_trace(tracer->capture_session, &trace_buffer, &trace_length)) < 0) {
        LOG_F("Could not get trace buffer on cpu=%d, error=%d\n", run->fuzzNo, result);
    }

    //FIXME: Do not hardcode the slide address
    if ((result = ha_session_reconfigure_with_terminated_trace_buffer(tracer->analysis_session,
                                                        trace_buffer,
                                                        trace_length,
                                                        run->global->honeybee_config.range_start)) >= 0) {
        /* We were able to sync */
        if ((result = ha_session_decode(tracer->analysis_session, process_block, run)) < 0
            && result != -HA_PT_DECODER_END_OF_STREAM) {
//            FILE *f = fopen("/tmp/o.pt", "w+");
//            fwrite(trace_buffer, trace_length, 1, f);
//            fclose(f);

            LOG_E("ipt decode error on cpu=%d, error=%d\n", run->fuzzNo, result);
        }

//        LOG_E("len = %llu\n", trace_length);
    }

    //Resume tracing
    if ((result = ha_capture_session_set_trace_enable(tracer->capture_session, 0x1, 0x1)) < 0) {
        LOG_F("Could not resume tracing on cpu=%d, error=%d\n", run->fuzzNo, result);
    }
}
