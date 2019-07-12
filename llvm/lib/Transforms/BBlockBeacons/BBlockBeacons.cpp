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
  struct BBlockBeaconsPass : public FunctionPass {
    static char ID; // Pass identification, replacement for typeid
    std::unique_ptr<RandomNumberGenerator> rng;
    std::unique_ptr<raw_fd_ostream> fh;
    std::error_code EC;
    BBlockBeaconsPass() : FunctionPass(ID) {}

    bool doInitialization(Module &M) override {
      // void _fnInterceptor_exit_(int64_t Function_id)
      M.getOrInsertFunction("_llvm_beacon_enter_", Type::getVoidTy(M.getContext()), IntegerType::get(M.getContext(),64));
			   
      rng = M.createRNG(this);
      fh = make_unique<raw_fd_ostream>(M.getName().str() + ".bndesc", EC);
      return true;
    }
    bool runOnFunction(Function &F) override {

      Module *M = F.getParent();
      if (F.hasFnAttribute(Attribute::AlwaysInline)) {
	return false;
      }

      if (F.getInstructionCount() < 100) {
	return false;
      }

      uint64_t fId = (*rng)();
      std::stringstream ss;
      ss << "0x" << std::hex << fId << " " << F.getName().str() << "\n";
      (*fh) << ss.str();

      Function *fn_beacon_enter = M->getFunction("_llvm_beacon_enter_");
      Value *funcId = ConstantInt::get(IntegerType::get(M->getContext(),64), fId);

      for (BasicBlock &B: F) {
	// insert the call in 1/8 of the blocks
	if ((*rng)() & 0x7) {
	  continue;
	}
	for(Instruction &I: B) {	  
	  IRBuilder<> Builder(&I);
	  IntegerType *int_type = Type::getInt64Ty(M->getContext());
	  ArrayRef<Value*> args{funcId};
	  Builder.CreateCall(fn_beacon_enter, args, "", NULL);
	  break;
	}
      }
      return true;
    }
  };
}

char BBlockBeaconsPass::ID = 0;
//static RegisterPass<BBlockBeaconsPass> X("fnInterceptor", "function interceptor");
static void registerBBlockBeaconsPass(const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
  PM.add(new BBlockBeaconsPass());
}

static RegisterStandardPasses RegisterBBlockBeaconsPass(PassManagerBuilder::EP_EarlyAsPossible, registerBBlockBeaconsPass);
