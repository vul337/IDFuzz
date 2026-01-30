/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.
*/

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <cassert>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>

using namespace llvm;

static std::string base_dir;
static std::string TargetsFile;
static std::string TargetsFile_inter;
static std::string OutFile;
static std::string OutFile2;

struct BlockInfo {
  BlockAddress *BlockAddr;
  unsigned int BlockId;
  unsigned int BlockLevel;
  SmallVector<unsigned int, 16> BranchID;
};

namespace {

  class AFLCoverage : public ModulePass {

    public:
      SmallVector<BlockInfo, 16> AFLBlockInfoVec;
      SmallVector<unsigned int, 16> DominatorBBid;
      std::map<unsigned int, std::vector<std::string>> DomId2target; // a dominator can dominate multiple targets
      SmallVector<unsigned int, 16> TargetBBid;
      std::map<unsigned int, std::vector<std::string>> Id2target; 
      BlockInfo *getBlockInfo(BasicBlock *BB);

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;
      void getAnalysisUsage(AnalysisUsage &AU) const override {
        AU.addRequired<DominatorTreeWrapperPass>();
      }

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };

}


char AFLCoverage::ID = 0;

static void getDebugLoc(const Instruction *I, std::string &Filename,
                        unsigned &Line) {
  if (DILocation *Loc = I->getDebugLoc()) {
    Line = Loc->getLine();
    Filename = Loc->getFilename().str();

    if (Filename.empty()) {
      DILocation *oDILoc = Loc->getInlinedAt();
      if (oDILoc) {
        Line = oDILoc->getLine();
        Filename = oDILoc->getFilename().str();
      }
    }
  }
}

bool AFLCoverage::runOnModule(Module &M) {
  const char* tmp_dir = std::getenv("TMP_DIR");
  if (!tmp_dir) base_dir = "/root";
  else base_dir = tmp_dir;
  TargetsFile = base_dir + "/BBtargets.txt";
  TargetsFile_inter = base_dir + "/BBtargets-inter.txt";
  OutFile = base_dir + "/DominatorsOfTargets.txt";
  OutFile2 = base_dir + "/ins.txt";
  /* Set output file */

  std::vector<BasicBlock *> BlockList;
  std::ofstream fdom;
  fdom.open(OutFile, std::ios::app);
  std::ofstream fdom2;
  fdom2.open(OutFile2, std::ios::app);

  /* ************************************************
   * Load intra-procedural targets
   * ************************************************/
  std::list<std::string> targets;
  std::list<std::string> targets_direct;
  if (!TargetsFile.empty()) {
    std::ifstream targetsfile(TargetsFile);
    std::string line;
    while (std::getline(targetsfile, line)) {
      // a valid line must have a ":"
      std::size_t found = line.find_last_of(":");
      if (found != std::string::npos) {
        targets.push_back(line);
        targets_direct.push_back(line);
      }
    }
    targetsfile.close();
  } else {
    errs() << "BB TargetsFile empty!\n";
  }

  if (!TargetsFile_inter.empty()) {
    std::ifstream targetsfile(TargetsFile_inter);
    std::string line;
    while (std::getline(targetsfile, line)) {
      // a valid line must have a ":"
      std::size_t found = line.find_last_of(":");
      // src:line_nb is after ","
      std::size_t found_comma = line.find_last_of(",");
      if ((found != std::string::npos) && (found_comma != std::string::npos)) {
        targets.push_back(line.substr(found_comma + 1));
      }
    }
    targetsfile.close();
  } else {
    errs() << "Inter-procedural TargetsFile empty!\n";
  }

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by anon.\n");

  } else be_quiet = 1;

  /* we make this the default as the fixed map has problems with
     defered forkserver, early constructors, ifuncs and maybe more */

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");


  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M) {
    if (!F.isDeclaration() && !F.empty()) {
      auto &DT = getAnalysis<DominatorTreeWrapperPass>(F).getDomTree();
      errs() << cCYA "[*] DominatorTree generated for function: " << F.getName() << "\n" cRST;
      std::vector<BasicBlock *> InsBlocks;
      for (auto &BB : F) {
        if (F.size() == 1) {
          InsBlocks.push_back(&BB);
        } else {
          uint32_t succ = 0;
          for (succ_iterator SI = succ_begin(&BB), SE = succ_end(&BB); SI != SE;
               ++SI)
            if ((*SI)->size() > 0)
              succ++;
          if (succ < 1) // no need to instrument
            continue;
          InsBlocks.push_back(&BB);
        }
        unsigned int cur_loc = AFL_R(MAP_SIZE);

        /*****  Get dominatees *****/
        SmallVector<BasicBlock *, 8> Descendants;
        BasicBlock *curr_bb = &BB;
        auto node = DT.getNode(curr_bb);
        unsigned curr_level = node->getLevel();
        DT.getDescendants(curr_bb, Descendants);
        BlockInfo CurBlockInfo;
        CurBlockInfo.BlockAddr = BlockAddress::get(&BB);
        CurBlockInfo.BlockId = cur_loc;
        CurBlockInfo.BlockLevel = curr_level;
        AFLBlockInfoVec.push_back(CurBlockInfo);
        std::string curr_filename = "";
        unsigned curr_line = 0;
        static const std::string Xlibs("/usr/");

        /* Find the first valid instruction and name the bb with the
         * corresponding filename and line number*/
        for (auto &I : BB) {
          getDebugLoc(&I, curr_filename, curr_line);

          /* Remove path prefix such as "./" */
          std::size_t found = curr_filename.find_last_of("/\\");
          if (found != std::string::npos)
            curr_filename = curr_filename.substr(found + 1);

          if (curr_filename.empty() || curr_line == 0 || !curr_filename.compare(0, Xlibs.size(), Xlibs))
            continue;
          for (auto &target : targets_direct) {
            std::size_t found = target.find_last_of("/\\");
            if (found != std::string::npos)
              target = target.substr(found + 1);
            std::size_t pos = target.find_last_of(":");
            std::string target_file = target.substr(0, pos);
            unsigned int target_line = atoi(target.substr(pos + 1).c_str());

            if (target_file == curr_filename && target_line == curr_line) {
              errs() << cGRN "[*] Found direct_target bb: " << curr_filename << ":"
                      << curr_line << " | bb id: " << cur_loc
                      << " | Level: " << curr_level << "\n" cRST;
              TargetBBid.push_back(cur_loc);
              Id2target[cur_loc].push_back(curr_filename + ":" + std::to_string(curr_line));
            }
          }
        }

        /********* Check targets and save cur_loc *********/
        for (auto &bb : Descendants) {
          std::string filename;
          unsigned line;

          for (auto &bbi : *bb) {
            getDebugLoc(&bbi, filename, line);

            /* Remove path prefix */
            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            /* Skip external libs */
            static const std::string Xlibs("/usr/");
            if (filename.empty() || line == 0 || !filename.compare(0, Xlibs.size(), Xlibs))
              continue;

            for (auto &target : targets) {
              std::size_t found = target.find_last_of("/\\");
              if (found != std::string::npos)
                target = target.substr(found + 1);
              std::size_t pos = target.find_last_of(":");
              std::string target_file = target.substr(0, pos);
              unsigned int target_line = atoi(target.substr(pos + 1).c_str());

              if (target_file == filename && target_line == line) {
                errs() << cGRN "[*] Found target bb: " << filename << ":"
                       << line << "\n" cRST;
                errs() << cGRN "[*] Current bb: " << curr_filename << ":"
                       << curr_line << " | bb id: " << cur_loc
                       << " | Level: " << curr_level << "\n" cRST;
                DominatorBBid.push_back(cur_loc);
                DomId2target[cur_loc].push_back(filename + ":" + std::to_string(line));
              }
            }
          }
        }
      }

      if (InsBlocks.size() > 0) {
        uint32_t i = InsBlocks.size();
        do {
          --i;
          BasicBlock *newBB = NULL;
          BlockInfo *ptrSuccessorBBInfo = NULL;
          BasicBlock *origBB = &(*InsBlocks[i]);
          std::vector<BasicBlock *> Successors;
          Instruction *TI = origBB->getTerminator();
          uint32_t fs = origBB->getParent()->size();
          uint32_t countto;
          BlockInfo *ptrCurrentBBInfo = getBlockInfo(origBB);
          unsigned int CurrentBBid = ptrCurrentBBInfo->BlockId;

          int flag = 0;
          int flag_target = 0;
          for (auto TargetID : TargetBBid) {
            if (TargetID == CurrentBBid) {
              flag_target = 1;
              break;
            }
          }
          for (auto DominatorID : DominatorBBid) {
            if (DominatorID == CurrentBBid) {
              flag = 1;
              break;
            }
          }
          if (flag) {
            errs() << "current bb ID:" << CurrentBBid << " Level: " << ptrCurrentBBInfo->BlockLevel << "\n";
          }

          uint32_t num_succ = 0;

          for (succ_iterator SI = succ_begin(origBB), SE = succ_end(origBB);
               SI != SE; ++SI) {
            if ((*SI)->size() > 0)
              num_succ++;

            BasicBlock *succ = *SI;
            Successors.push_back(succ);
          }
          if (num_succ == 1 && flag_target == 0) continue;

          if (fs == 1) {
            newBB = origBB;
            countto = 1;
          } else {
            if (TI == NULL || TI->getNumSuccessors() < 1)
              continue;
            if (TI->getNumSuccessors() == 1 && flag_target == 0)
              continue;
            countto = Successors.size();
          }

          for (uint32_t j = 0; j < countto; j++) {
            if (fs != 1) {
              newBB = llvm::SplitEdge(origBB, Successors[j]);
              ptrSuccessorBBInfo = getBlockInfo(Successors[j]);
            }
            if (!newBB) {
              if (!be_quiet) WARNF("Split failed!");
              continue;
            }
            int flag_succ = 0;
            unsigned int SuccessorBBId = 0;
            if(ptrSuccessorBBInfo) {
              SuccessorBBId = ptrSuccessorBBInfo->BlockId;
              if(SuccessorBBId!=CurrentBBid) {
                for (auto DominatorID : DominatorBBid) {
                  if (DominatorID == SuccessorBBId) {
                    flag_succ = 1;
                    break;
                  }
                }
                for (auto TargetID : TargetBBid) {
                  if (TargetID == SuccessorBBId) {
                    flag_succ = 1;
                    break;
                  }
                }
              }
            }
            BasicBlock::iterator IP = newBB->getFirstInsertionPt();
            IRBuilder<> IRB(&(*IP));

            /* Set the ID of the inserted basic block */

            unsigned int cur_edge = AFL_R(MAP_SIZE);
            ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_edge);
            fdom2<< cur_edge <<"\n";
            if (flag_target) {
              std::string filename1; // print bb2line
              unsigned line1;
              getDebugLoc(origBB->getTerminator(),filename1,line1);
              ptrCurrentBBInfo->BranchID.push_back(cur_edge);
              for (std::string target_direct : Id2target[CurrentBBid]) {
                errs() << "edge id:" << cur_edge << "\n";
                errs() << "current target:" << target_direct << "\n";
                fdom << "[*] Current bb: " << CurrentBBid
                    << " | Edge number: " << cur_edge
                    << " | Level: " << -1
                    << " | Target: " << target_direct
                    << " | Next bb dom: " << SuccessorBBId*flag_succ
                    << " | location: " <<filename1
                    << " :"<<line1
                    << "\n";
              }
            } else {
              if (flag) {
                std::string filename2; // print bb2line
                unsigned line2;
                getDebugLoc(origBB->getTerminator(),filename2,line2);
                ptrCurrentBBInfo->BranchID.push_back(cur_edge);
                for (std::string target : DomId2target[CurrentBBid]) {
                  errs() << "edge id:" << cur_edge << "\n";
                  errs() << "current target:" << target << "\n";
                  fdom << "[*] Current bb: " << CurrentBBid
                      << " | Edge number: " << cur_edge
                      << " | Level: " << ptrCurrentBBInfo->BlockLevel
                      << " | Target: " << target
                      << " | Next bb dom: " << SuccessorBBId*flag_succ
                      << " | location: " <<filename2
                      << " :"<<line2
                      << "\n";
                }
              }
            }

            /* Load SHM pointer */

            LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
            MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *MapPtrIdx = IRB.CreateGEP(MapPtr, CurLoc);

            /* Update bitmap */

            LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
            Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
            IRB.CreateStore(Incr, MapPtrIdx)
                ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            // done :)
            inst_blocks++;
          }
        } while (i > 0);
      }
    } else {
      errs() << cRED "[*] Empty function!" << F.getName() << "\n" cRST;
    }
  }

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
             ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
              "ASAN/MSAN" : "non-hardened"), 100);

  }

  fdom.close();
  return true;

}

// iterate the vec to get the corresponding random BBlockId by BB class
// rvalue is BBlockId
BlockInfo *AFLCoverage::getBlockInfo(BasicBlock *BB) {
  // get the addr of this preBlock in order to get the BlockId of this addr
  BlockAddress *BlcAddr = BlockAddress::get(BB);
  // iterate the vec to get the corresponding BlockId
  for (auto &I : AFLBlockInfoVec) {
    if (I.BlockAddr == BlcAddr) {
      return &I;
    }
  }
  errs() << "There is no corresponding BB in the array\n";
  return nullptr;
}

static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
