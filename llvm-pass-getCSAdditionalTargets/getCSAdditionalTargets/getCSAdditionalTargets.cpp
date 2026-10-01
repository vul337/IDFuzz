#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>
#include <fstream>
#include <iostream>
#include <cstdlib>

using namespace llvm;

static std::string getEnvPath(const char* envVar, const std::string& defaultPath) {
  const char* envValue = std::getenv(envVar);
  return envValue ? std::string(envValue) : defaultPath;
}

static std::string tmpDir = getEnvPath("TMP_DIR", "/tmp");

static cl::opt<std::string>
    TargetsFile("targets",
                cl::desc("Input file containing the target functions: "
                         "<file_name>:<line_number>,func1,func2,...,main"),
                cl::value_desc("targets"),
                cl::init(tmpDir + "/DominatorsOfTargetFunctions.txt"));

cl::opt<std::string> OutFile(
    "out", cl::desc("Output File containing functions of the targets."),
    cl::value_desc("out"), cl::init(tmpDir + "/BBtargets-inter.txt"));



static void getDebugLoc(const Instruction *I, std::string &Filename, unsigned &Line) {
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

static std::vector<std::vector<std::string>> get_func_targets(){
  std::vector<std::vector<std::string>> func_targets;

  if (!TargetsFile.empty()) {
    std::ifstream targetsfile(TargetsFile);
    std::string line;
    while (std::getline(targetsfile, line)){
      std::string read_line = line; // "bof.c:23,doit,main"
      while(1){
        // a valid line must have a ","
        std::size_t found = read_line.find_last_of(",");
        if (found == std::string::npos) break;
        std::string caller = read_line.substr(found+1); // "main"
        std::string left = read_line.substr(0,found); // "bof.c:23,doit"
        std::size_t found_left = left.find_last_of(",");
        if (found_left != std::string::npos){
          std::string callee = left.substr(found_left+1); // "doit"
          std::vector<std::string> pair = {caller,callee}; // {"main","doit"}
          errs()<< "caller: " << caller << " -> callee: " << callee << "\n";
          func_targets.push_back(pair);
          read_line = left; // "bof.c:23,doit"
        } else { break; }
      }
    }
  }
  return func_targets;
}

namespace {
  struct getCSAdditionalTargets : public ModulePass {

    static char ID;

    getCSAdditionalTargets() : ModulePass(ID) {}

    bool runOnModule(Module &M) override;

  }; // end of struct
}  // end of anonymous namespace

char getCSAdditionalTargets::ID = 0;

bool getCSAdditionalTargets::runOnModule(Module &M){
  // Read the targets here rather than at plugin load time, so that -targets
  // given on the command line is honored.
  // (N*M,2) N is the number of target basic blocks, M is the number of caller/callee pairs
  std::vector<std::vector<std::string>> func_targets = get_func_targets();

  // opt runs this pass once on the whole-program bitcode, so start a fresh file.
  std::ofstream ftarget;
  ftarget.open(OutFile, std::ios::trunc);

  for (auto tuple : func_targets){
    std::string caller = tuple[0];
    std::string callee = tuple[1];
    Function *F = M.getFunction((StringRef)caller);
    if (!F || F->isDeclaration()) {
      errs() << "warning: caller " << caller << " is not defined in this module, skipping "
             << caller << " -> " << callee << "\n";
      continue;
    }

    for (auto &BB : *F){

      /* Find the first valid instruction and name the bb with the
      * corresponding filename and line number*/
      std::string bb_head = "";
      std::string curr_filename = "";
      unsigned curr_line = 0;
      static const std::string Xlibs("/usr/");
      for (auto &I : BB) {
        getDebugLoc(&I, curr_filename, curr_line);

        /* Remove path prefix such as "./" */
        std::size_t found = curr_filename.find_last_of("/\\");
        if (found != std::string::npos)
          curr_filename = curr_filename.substr(found + 1);
        if (curr_filename.empty() || curr_line == 0 || !curr_filename.compare(0, Xlibs.size(), Xlibs))
          continue;
        else {
          bb_head = curr_filename + ":" + std::to_string(curr_line);
          break;
        }
      }

      for (auto &I : BB){
        // CallBase covers call and invoke (C++ code with exceptions). Strip
        // casts so direct calls through a bitcast function type are found too.
        if (auto *c = dyn_cast<CallBase>(&I)){
          if (auto *CalledF = dyn_cast<Function>(c->getCalledOperand()->stripPointerCasts())){
            if (CalledF->getName().str() == callee){
                getDebugLoc(&I,curr_filename,curr_line);
                /* Remove path prefix such as "./" */
                std::size_t found = curr_filename.find_last_of("/\\");
                if (found != std::string::npos)
                  curr_filename = curr_filename.substr(found + 1);
                errs() << "caller: " << caller << ",callee: " << callee << "\n";
                errs() << "\tCallSite " << curr_filename << ":" << curr_line << ", in function " << caller << "\n";
                ftarget << caller << " -> " << callee << "," << curr_filename << ":" << curr_line << "\n";
            }
          } 
        }
      }
    }
  }

  ftarget.close();
  return 0;
}



static RegisterPass<getCSAdditionalTargets> X("getCSAdditionalTargets", "Get Function Name Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);