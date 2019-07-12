//===- FnInterceptor.cpp - Example code from "Writing an LLVM Pass" ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements two versions of the LLVM "Hello World" pass described
// in docs/WritingAnLLVMPass.html
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Constants.h"
#include "llvm/ADT/APInt.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/Instructions.h"
#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <sstream>
using namespace llvm;


namespace {
  // Hello - The first implementation, without getAnalysisUsage.
  // Intercept Function entry and exit
  // adds a call right at entry and one right before exit
  struct FnInterceptorPass : public FunctionPass {
    static char ID; // Pass identification, replacement for typeid
    std::unique_ptr<RandomNumberGenerator> rng;
    std::unique_ptr<raw_fd_ostream> fh;
    std::error_code EC;
    FnInterceptorPass() : FunctionPass(ID) {}

    bool doInitialization(Module &M) override {
      // long long  _fnInterceptor_entry_(void)
      M.getOrInsertFunction("_fnInterceptor_entry_", IntegerType::get(M.getContext(),64));
      // void _fnInterceptor_exit_(int64_t Function_id, int64_t start_time)
      M.getOrInsertFunction("_fnInterceptor_exit_", Type::getVoidTy(M.getContext()), IntegerType::get(M.getContext(),64),
			    IntegerType::get(M.getContext(),64));
      // void _fnInterceptor_stack_(int64_t ident, int64_t stack_size);
      M.getOrInsertFunction("_fnInterceptor_stack_", Type::getVoidTy(M.getContext()), IntegerType::get(M.getContext(),64),
			    IntegerType::get(M.getContext(),64));
      rng = M.createRNG(this);
      srand(time(NULL));
      fh = make_unique<raw_fd_ostream>(M.getName().str() + ".fndesc", EC);
      return true;
    }
    bool runOnFunction(Function &F) override {
      /*
      for(inst_iterator I = inst_begin(F), E = inst_end(F); I!=E;++I) {
	if (auto *retIns = dyn_cast<ReturnInst>(&*I)) {
	  errs() << "Found Ret\n";
	}
      }
      */
      Module *M = F.getParent();
      if (F.hasFnAttribute(Attribute::AlwaysInline)) {
	return false;
      }
      // XOR two random numbers to make sure we get a unique ID
      uint64_t fId = (*rng)() ^ (rand() << 32);
      std::stringstream ss;
      ss << "0x" << std::hex << fId << " " << F.getName().str() << "\n";
      (*fh) << ss.str();

      Function *fn_intercept_exit = M->getFunction("_fnInterceptor_exit_");
      Value *funcId = ConstantInt::get(IntegerType::get(M->getContext(),64), fId);
      SmallVector<Value*,1> argsv{funcId};
      Function *fn_intercept_enter = M->getFunction("_fnInterceptor_entry_");
      Value *t0;

      Function *fn_stack_size = M->getFunction("_fnInterceptor_stack_");

      // function foo(...) {
      // int t0 = _fn_intercept_enter_();
      // ...
      // _fn_intercept_exit_(function_identifier, t0)


      bool firstInstr = true;
      Value *firstStackElement;
      int randomSeed = (*rng)();
      for (BasicBlock &B: F) {
	for(Instruction &I: B) {

	  if (firstInstr) {
	    firstInstr = false;
	    IRBuilder<> Builder(&I);
	    IntegerType *int_type = Type::getInt64Ty(M->getContext());
	    firstStackElement = new AllocaInst(int_type, 0, "", &I);
	    ArrayRef<Value*> voidarg;
	    t0 = Builder.CreateCall(fn_intercept_enter, voidarg, "", NULL);
	    argsv.push_back(t0);
	  }

	  if (auto *retInst = dyn_cast<ReturnInst>(&I)) {
	    
	    IRBuilder<> Builder(retInst);
	    {
	      ArrayRef<Value*> args(argsv);
	      CallInst *callexit = Builder.CreateCall(fn_intercept_exit, args, "", NULL);
	    }
	    IntegerType *int_type = Type::getInt64Ty(M->getContext());
	    AllocaInst *newStackElement = Builder.CreateAlloca(int_type);
	    Value *bottom = Builder.CreatePtrToInt(newStackElement, int_type);
	    Value *top = Builder.CreatePtrToInt(firstStackElement, int_type);
	    Value *diff = Builder.CreateSub(top, bottom);
	    ArrayRef<Value*> args{top, bottom};
	    Builder.CreateCall(fn_stack_size, args, "", NULL);	    
	  }

	  // measure the stack size at random places in the code
	}
      }
      return true;
    }
  };
}

char FnInterceptorPass::ID = 0;
//static RegisterPass<FnInterceptorPass> X("fnInterceptor", "function interceptor");
static void registerFnInterceptorPass(const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
  PM.add(new FnInterceptorPass());
}

static RegisterStandardPasses RegisterFnInterceptorPass(PassManagerBuilder::EP_EarlyAsPossible, registerFnInterceptorPass);
