// JOCKY LLVM Pass --- Control-Flow Flattening
//
// This pass transforms any function into a dispatcher-based state machine.
// Every basic block becomes a case in a switch statement. The original
// control-flow graph is destroyed, replaced by a single dispatcher loop.
//
// This is exactly what O-LLVM's -fla pass does.

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdio>

#include <map>
#include <vector>

using namespace llvm;

namespace {

struct FlattenCFGPass : public PassInfoMixin<FlattenCFGPass> {

    PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM) {
        // Skip declarations and functions with no body
        if (F.isDeclaration()) {
            return PreservedAnalyses::all();
        }

        // Skip functions with fewer than 2 basic blocks (nothing to flatten)
        if (F.size() < 2) {
            return PreservedAnalyses::all();
        }

        // Skip our own main --- we only flatten user functions
        // (This is optional; remove if you want to flatten everything)
        if (F.getName() == "main") {
            return PreservedAnalyses::all();
        }

        fprintf(stderr, "[FlattenCFG] Flattening function: %s (blocks=%u)\n",
                F.getName().str().c_str(), (unsigned)F.size());
        fflush(stderr);
        // --- Step 1: Collect all basic blocks except the entry ---
        std::vector<BasicBlock*> Blocks;
        for (BasicBlock &BB : F) {
            if (&BB != &F.getEntryBlock()) {
                Blocks.push_back(&BB);
            }
        }

        if (Blocks.empty()) {
            return PreservedAnalyses::all();
        }

        // --- Step 2: Create the dispatcher block ---
        LLVMContext &Ctx = F.getContext();
        BasicBlock *Entry = &F.getEntryBlock();

        // Allocate state variable at the top of the entry block
        IRBuilder<> EntryBuilder(&*Entry->getFirstInsertionPt());
        AllocaInst *StateVar = EntryBuilder.CreateAlloca(
            Type::getInt32Ty(Ctx), nullptr, "jocky_state");

        // Initialize state to 0
        EntryBuilder.CreateStore(
            ConstantInt::get(Type::getInt32Ty(Ctx), 0), StateVar);

        // Create the dispatcher block (after entry)
        BasicBlock *Dispatcher = BasicBlock::Create(
            Ctx, "jocky_dispatcher", &F);

        // Create an exit block for returns
        BasicBlock *ExitBlock = BasicBlock::Create(
            Ctx, "jocky_exit", &F);

        // --- Step 3: Build the switch in the dispatcher ---
        IRBuilder<> DispBuilder(Dispatcher);
        LoadInst *CurrentState = DispBuilder.CreateLoad(
            Type::getInt32Ty(Ctx), StateVar, "current_state");

        // Create a switch with N cases (one per original block)
        SwitchInst *Switch = DispBuilder.CreateSwitch(
            CurrentState, ExitBlock, Blocks.size());

        // --- Step 4: Assign each original block a case number ---
        std::map<BasicBlock*, int> BlockIDs;
        for (size_t i = 0; i < Blocks.size(); i++) {
            BlockIDs[Blocks[i]] = (int)i;
            Switch->addCase(
                ConstantInt::get(Type::getInt32Ty(Ctx), (int)i),
                Blocks[i]);
        }

        // --- Step 5: Rewrite terminators in each block ---
        // Instead of branching to another block, we set the state variable
        // and jump back to the dispatcher.
        for (BasicBlock *BB : Blocks) {
            Instruction *Term = BB->getTerminator();
            if (!Term) continue;

            IRBuilder<> BBuilder(Term);

            if (auto *Br = dyn_cast<BranchInst>(Term)) {
                if (Br->isUnconditional()) {
                    // Set state to the target's ID, then jump to dispatcher
                    BasicBlock *Target = Br->getSuccessor(0);
                    auto It = BlockIDs.find(Target);
                    if (It != BlockIDs.end()) {
                        BBuilder.CreateStore(
                            ConstantInt::get(Type::getInt32Ty(Ctx), It->second),
                            StateVar);
                    }
                    BBuilder.CreateBr(Dispatcher);
                } else if (Br->isConditional()) {
                    // For conditional branches, we need to select state
                    // based on the condition.
                    BasicBlock *TrueBB = Br->getSuccessor(0);
                    BasicBlock *FalseBB = Br->getSuccessor(1);

                    Value *Cond = Br->getCondition();

                    // Create blocks for the true/false paths
                    BasicBlock *TruePath = BasicBlock::Create(
                        Ctx, "jocky_true", &F);
                    BasicBlock *FalsePath = BasicBlock::Create(
                        Ctx, "jocky_false", &F);

                    IRBuilder<> TB(TruePath);
                    auto TrueIt = BlockIDs.find(TrueBB);
                    if (TrueIt != BlockIDs.end()) {
                        TB.CreateStore(
                            ConstantInt::get(Type::getInt32Ty(Ctx), TrueIt->second),
                            StateVar);
                    }
                    TB.CreateBr(Dispatcher);

                    IRBuilder<> FB(FalsePath);
                    auto FalseIt = BlockIDs.find(FalseBB);
                    if (FalseIt != BlockIDs.end()) {
                        FB.CreateStore(
                            ConstantInt::get(Type::getInt32Ty(Ctx), FalseIt->second),
                            StateVar);
                    }
                    FB.CreateBr(Dispatcher);

                    // Replace the original conditional branch
                    BBuilder.CreateCondBr(Cond, TruePath, FalsePath);
                }
            } else if (auto *Ret = dyn_cast<ReturnInst>(Term)) {
                // For returns, we jump to the exit block
                // The exit block will hold the actual return
                BBuilder.CreateBr(ExitBlock);
            }

            // Delete the old terminator
            Term->eraseFromParent();
        }

        // --- Step 6: Build the exit block ---
        // The exit block returns whatever the function was supposed to return.
        // For simplicity, we return the value from the original entry's return
        // (if any). Otherwise, return void.
        IRBuilder<> ExitBuilder(ExitBlock);
        if (F.getReturnType()->isVoidTy()) {
            ExitBuilder.CreateRetVoid();
        } else {
            // Return a default value (0 for int, null for pointers)
            if (F.getReturnType()->isIntegerTy()) {
                ExitBuilder.CreateRet(
                    ConstantInt::get(F.getReturnType(), 0));
            } else if (F.getReturnType()->isPointerTy()) {
                ExitBuilder.CreateRet(
                    ConstantPointerNull::get(
                        cast<PointerType>(F.getReturnType())));
            } else {
                ExitBuilder.CreateRetVoid();
            }
        }

        // --- Step 7: Ensure entry block jumps to dispatcher ---
        // The entry block originally fell through or branched to the first real block.
        // We need it to set state = 0 (or the first block's ID) and jump to dispatcher.
        // The state was already initialized to 0, so we just branch to dispatcher.
        IRBuilder<> EntryTerm(&*Entry->getTerminator());
        // The entry's original terminator is still there; we need to replace it.
        // Actually, we need to be careful: the entry block's terminator might be
        // a branch to the first real block. We already handled that in Step 5
        // because the first real block is in `Blocks`. But the entry block itself
        // is not in `Blocks`. So its terminator needs to be replaced.
        Instruction *EntryTerm_ = Entry->getTerminator();
        if (EntryTerm_) {
            IRBuilder<> EB(EntryTerm_);
            EB.CreateBr(Dispatcher);
            EntryTerm_->eraseFromParent();
        }

        return PreservedAnalyses::none();
    }
};

} // namespace

// --- Plugin registration ---
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "FlattenCFG", LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "flatten-cfg") {
                        FPM.addPass(FlattenCFGPass());
                        return true;
                    }
                    return false;
                });
        }
    };
}
