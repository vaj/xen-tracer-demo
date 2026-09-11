/*
 * xen/arch/arm/arm64/livepatch-asm.S
 *
 * Trampoline for livepatch tracer.
 *
 * Ryo Takakura <takakura@valinux.co.jp>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
/*
 * If livepatch tracer is enabled, function entries are placed
 * with two NOPs. Once user requests a functions to be traced,
 * arch_livepatch_apply_trace() will livepatch those NOPs to:
 *
 *     mov     x9, x30
 *     bl      xen_livepatch_trace_caller
 *
 * x9  = traced function's original LR
 * x30 = traced function + 8
 */
FUNC(xen_livepatch_trace_caller)
        /*
         * Registers to save/restore:
         *
         *   x0-x8          Function arguments
         *   x9             Original LR
         *   x29            Original FP
         *   x30            PC to return
         */
        sub     sp, sp, #96

        /* Save function arguments */
        stp     x0, x1,   [sp, #0]
        stp     x2, x3,   [sp, #16]
        stp     x4, x5,   [sp, #32]
        stp     x6, x7,   [sp, #48]
        str     x8,       [sp, #64]

        /* Save LR, FP, PC */
        str     x9,       [sp, #72]
        str     x29,      [sp, #80]
        str     x30,      [sp, #88]

        /*
         * xen_livepatch_trace_dispatcher(ip, parent_ip)
         *
         * ip: Instruction pointer of the function being traced.
         * parent_ip: Instruction pointer of the function which
         *            called the function being traced.
         */
        sub     x0, x30, #8
        mov     x1, x9
        bl      xen_livepatch_trace_dispatcher

        /* Restore function arguments */
        ldp     x0, x1, [sp, #0]
        ldp     x2, x3, [sp, #16]
        ldp     x4, x5, [sp, #32]
        ldp     x6, x7, [sp, #48]
        ldr     x8,     [sp, #64]

        /* Restore FP, LR, PC */
        ldr     x29,    [sp, #80]
        ldr     x30,    [sp, #72]
        ldr     x9,     [sp, #88]

        /* Restore SP */
        add     sp, sp, #96

        /* ret x9 */
        .inst   0xd65f0120
        sb
END(xen_livepatch_trace_caller)
