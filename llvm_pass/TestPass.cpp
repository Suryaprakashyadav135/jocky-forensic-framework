#include "llvm/IR/Function.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdio>

using namespace llvm;

namespace {
struct TestPass : public PassInfoMixin<TestPass> {
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM) {
        // Use BOTH stderr and stdout to make sure output isn't swallowed
        fprintf(stderr, "[TestPass-STDERR] SAW: %s (blocks=%u, decl=%d)\n",
                F.getName().str().c_str(), (unsigned)F.size(), F.isDeclaration());
        fprintf(stdout, "[TestPass-STDOUT] SAW: %s (blocks=%u)\n",
                F.getName().str().c_str(), (unsigned)F.size());
        fflush(stderr);
        fflush(stdout);
        return PreservedAnalyses::all();
    }
};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "TestPass", LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "test-print") {
                        FPM.addPass(TestPass());
                        return true;
                    }
                    return false;
                });
        }
    };
}
