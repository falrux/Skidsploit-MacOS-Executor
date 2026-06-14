#pragma once
#include <cstdint>
#include <memory>

namespace Structures {

    struct SharedString {
        uintptr_t data[4];
    };

    struct ObjectRef {
        uintptr_t data[2];
    };

    struct LiveThreadRef {
        uintptr_t padding[3];
        uintptr_t unk;
        uintptr_t padding1;
        void     *Thread;
        int       ThreadRef;
        int       FunctionRef;
    };

    struct WeakObjectRef {
        void                       *vftable;
        uint32_t                    state;
        uint32_t                    padding;
        LiveThreadRef              *LiveThread;
        std::__shared_weak_count   *WeakCount;
    };

    struct WeakThreadRef {
        void                       *vftable;
        uint32_t                    state;
        uint32_t                    padding;
        LiveThreadRef              *LiveThread;
        std::__shared_weak_count   *WeakCount;
    };

    struct Variant {
        uintptr_t data[8];
    };

} // namespace Structures
