#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include <set>

using namespace llvm;

namespace
{
struct MyTaintPass : public ModulePass
{
    static char ID;
    MyTaintPass() : ModulePass(ID)
    {
    }

    bool runOnModule(Module &M) override
    {
        outs() << "Now we're in the DTA Pass\n";
        LLVMContext &Ctx = M.getContext();
        const DataLayout &DL = M.getDataLayout();
        unsigned ptrSize = DL.getPointerSizeInBits();
        Type *sizeTTy = Type::getIntNTy(Ctx, ptrSize);

        // 创建类型特定的日志函数
        FunctionCallee LogFunc_i8 = createLogFunction(M, Type::getInt8Ty(Ctx));
        FunctionCallee LogFunc_i16 = createLogFunction(M, Type::getInt16Ty(Ctx));
        FunctionCallee LogFunc_i32 = createLogFunction(M, Type::getInt32Ty(Ctx));
        FunctionCallee LogFunc_i64 = createLogFunction(M, Type::getInt64Ty(Ctx));

        // 定义 read 的 hook 函数
        // 函数原型：ssize_t read (int __fd, void *__buf, size_t __nbytes)
        FunctionType *WrapReadTy =
            FunctionType::get(sizeTTy, {Type::getInt32Ty(Ctx), Type::getInt8PtrTy(Ctx), sizeTTy}, false);
        FunctionCallee MyRead = M.getOrInsertFunction("__my_read", WrapReadTy);

        // 定义 mmap 的 hook 函数
        // 函数类型：void* mmap(void*, size_t, int, int, int, off_t)
        FunctionType *MmapTy = FunctionType::get(Type::getInt8PtrTy(Ctx),
                                                 {Type::getInt8PtrTy(Ctx), sizeTTy, Type::getInt32Ty(Ctx),
                                                  Type::getInt32Ty(Ctx), Type::getInt32Ty(Ctx), sizeTTy},
                                                 false);
        FunctionCallee MyMmap = M.getOrInsertFunction("__my_mmap", MmapTy);

        // 定义 munmap 的 hook 函数
        // 函数原型：int munmap (void *__addr, size_t __len)
        FunctionType *UnmapTy = FunctionType::get(Type::getInt32Ty(Ctx), {Type::getInt8PtrTy(Ctx), sizeTTy}, false);
        FunctionCallee MyUnmap = M.getOrInsertFunction("__my_munmap", MmapTy);

        bool Modified = false;

        // 指定要分析的函数
        std::set<std::string> Targets = {"TIFFFdOpenExt", "mytest"};

        for (Function &F : M)
        {
            // 分析指定的函数
            if (!F.isDeclaration() && Targets.count(F.getName().str()))
            {
                // 分析 F 的参数
                Function *TargetFunc = M.getFunction(F.getName().str());
                for (auto &Arg : TargetFunc->args())
                {
                    // debug
                    // outs() << "Arg: " << Arg.getName() << " | Type: ";
                    // Arg.getType()->print(outs());
                    // outs() << "\n";

                    IRBuilder<> IRB(&*TargetFunc->getEntryBlock().getFirstInsertionPt());
                    if (Arg.getType()->isIntegerTy())
                    {
                        callLogFunction(IRB, &Arg, LogFunc_i8, LogFunc_i16, LogFunc_i32, LogFunc_i64);
                    }
                }
            }

            for (BasicBlock &BB : F)
            {
                for (auto I = BB.begin(), E = BB.end(); I != E;)
                {
                    Instruction &Inst = *I++;

                    // 处理 icmp 指令
                    if (auto *Cmp = dyn_cast<ICmpInst>(&Inst))
                    {
                        Value *Op1 = Cmp->getOperand(0);
                        Value *Op2 = Cmp->getOperand(1);
                        IRBuilder<> IRB(Cmp);

                        // debug
                        // outs() << *Cmp << "\n";

                        // 根据操作数类型选择正确的日志函数
                        if (Op1->getType()->isIntegerTy())
                            callLogFunction(IRB, Op1, LogFunc_i8, LogFunc_i16, LogFunc_i32, LogFunc_i64);
                        if (Op2->getType()->isIntegerTy())
                            callLogFunction(IRB, Op2, LogFunc_i8, LogFunc_i16, LogFunc_i32, LogFunc_i64);

                        Modified = true;
                    }

                    // 处理 switch 指令
                    else if (auto *SI = dyn_cast<SwitchInst>(&Inst))
                    {
                        Value *Cond = SI->getCondition();
                        IRBuilder<> IRB(SI);

                        if (Cond->getType()->isIntegerTy())
                            callLogFunction(IRB, Cond, LogFunc_i8, LogFunc_i16, LogFunc_i32, LogFunc_i64);

                        Modified = true;
                    }

                    // 处理 call 指令
                    else if (auto *CI = dyn_cast<CallInst>(&Inst))
                    {
                        Function *Callee = CI->getCalledFunction();
                        if (!Callee)
                            continue;
                        // 处理 read 调用
                        if (Callee->getName() == "read")
                        {
                            Value *fd = CI->getArgOperand(0);
                            Value *buf = CI->getArgOperand(1);
                            Value *count = CI->getArgOperand(2);
                            IRBuilder<> IRB(CI);

                            Value *NewCall = IRB.CreateCall(MyRead, {fd, buf, count});

                            // 替换原始调用
                            if (!CI->getType()->isVoidTy())
                                CI->replaceAllUsesWith(NewCall);
                            CI->eraseFromParent();

                            Modified = true;
                        }
                        // 处理 mmap 调用
                        else if (Callee->getName() == "mmap")
                        {
                            Value *addr = CI->getArgOperand(0);
                            Value *length = CI->getArgOperand(1);
                            Value *prot = CI->getArgOperand(2);
                            Value *flags = CI->getArgOperand(3);
                            Value *fd = CI->getArgOperand(4);
                            Value *offset = CI->getArgOperand(5);

                            IRBuilder<> IRB(CI);
                            Value *NewCall = IRB.CreateCall(MyMmap, {addr, length, prot, flags, fd, offset});

                            if (!CI->getType()->isVoidTy())
                                CI->replaceAllUsesWith(NewCall);
                            CI->eraseFromParent();

                            Modified = true;
                        }
                        // 处理 munmap 调用
                        else if (Callee->getName() == "munmap")
                        {
                            Value *addr = CI->getArgOperand(0);
                            Value *length = CI->getArgOperand(1);

                            IRBuilder<> IRB(CI);
                            Value *NewCall = IRB.CreateCall(MyUnmap, {addr, length});

                            if (!CI->getType()->isVoidTy())
                                CI->replaceAllUsesWith(NewCall);
                            CI->eraseFromParent();

                            Modified = true;
                        }
                    }
                }
            }
        }
        return Modified;
    }

  private:
    // 创建类型特定的日志函数
    FunctionCallee createLogFunction(Module &M, Type *Ty)
    {
        std::string FuncName = "__my_log_" + std::to_string(Ty->getIntegerBitWidth());
        return M.getOrInsertFunction(FuncName, FunctionType::get(Type::getVoidTy(M.getContext()), {Ty}, false));
    }

    // 根据类型调用正确的日志函数
    void callLogFunction(IRBuilder<> &IRB, Value *V, FunctionCallee Log_i8, FunctionCallee Log_i16,
                         FunctionCallee Log_i32, FunctionCallee Log_i64)
    {

        // debug
        // outs() << "Value: " << *V << "\n";

        Value *OriginalV = V;
        // 如果是符号扩展或零扩展，获取原始操作数
        if (auto *SExt = dyn_cast<SExtInst>(V))
        {
            OriginalV = SExt->getOperand(0);
        }
        else if (auto *ZExt = dyn_cast<ZExtInst>(V))
        {
            OriginalV = ZExt->getOperand(0);
        }

        Type *OrigTy = OriginalV->getType();
        unsigned BitWidth = OrigTy->getIntegerBitWidth();

        switch (BitWidth)
        {
        case 8:
            IRB.CreateCall(Log_i8, {OriginalV});
            break;
        case 16:
            IRB.CreateCall(Log_i16, {OriginalV});
            break;
        case 32:
            IRB.CreateCall(Log_i32, {OriginalV});
            break;
        case 64:
            IRB.CreateCall(Log_i64, {OriginalV});
            break;
        default:
            // 对于非常见类型，直接报错
            errs() << "Invalid type!\n";
            break;
        }
    }
};
} // namespace

char MyTaintPass::ID = 0;

static void registerMyPass(const PassManagerBuilder &, legacy::PassManagerBase &PM)
{
    PM.add(new MyTaintPass());
}

static RegisterStandardPasses RegisterMyPassOpt0(PassManagerBuilder::EP_EnabledOnOptLevel0, registerMyPass);
static RegisterStandardPasses RegisterMyPassOpt123(PassManagerBuilder::EP_OptimizerLast, registerMyPass);