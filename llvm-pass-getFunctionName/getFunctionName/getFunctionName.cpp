#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include <list>
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
                cl::desc("Input file containing the target lines of code: "
                         "<file_name>:<line_number>."),
                cl::value_desc("targets"),
                cl::init(tmpDir + "/BBtargets.txt"));

cl::opt<std::string> OutFile(
    "out", cl::desc("Output File containing functions of the targets."),
    cl::value_desc("out"), cl::init(tmpDir + "/FunctionsOfTargets.txt"));

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

static std::list<std::string> getTargets(){
  std::list<std::string> targets_load;
  if (!TargetsFile.empty()) {
    std::ifstream targetsfile(TargetsFile);
    std::string line;
    while (std::getline(targetsfile, line)){
      // a valid line must have a ":"
      std::size_t found = line.find_last_of(":");
      if (found != std::string::npos){
        targets_load.push_back(line);
        errs()<<"target: "<<line<<"\n";
      }
    }
    targetsfile.close();
  } else {
    errs() << "TargetsFile empty!\n";
  }
  return targets_load;
}

namespace {
struct getFunctionName : public FunctionPass {
  static char ID;
  static std::list<std::string> targets;  

  getFunctionName() : FunctionPass(ID) {}

  bool runOnFunction(Function &F) override;

}; // end of struct
}  // end of anonymous namespace

char getFunctionName::ID = 0;
std::list<std::string> getFunctionName::targets = getTargets();  

bool getFunctionName::runOnFunction(Function &F) {
  std::ofstream ftarget;
  ftarget.open(OutFile, std::ios::app);

  for (auto &BB : F) {
    std::string curr_filename = "";
    unsigned curr_line = 0;
    static const std::string Xlibs("/usr/");

    for (auto &I : BB) {
      getDebugLoc(&I, curr_filename, curr_line);

      /* Remove path prefix such as "./" */
      std::size_t found = curr_filename.find_last_of("/\\");
      if (found != std::string::npos)
        curr_filename = curr_filename.substr(found + 1);

      for (auto &target : targets) {
        
        std::size_t found = target.find_last_of("/\\");
        if (found != std::string::npos)
          target = target.substr(found + 1);
        std::size_t pos = target.find_last_of(":");
        std::string target_file = target.substr(0, pos);
        unsigned int target_line = atoi(target.substr(pos + 1).c_str());

        if (target_file == curr_filename && target_line == curr_line) {
          errs() << "In function " << F.getName().str() << ":\n";
          errs() << "\t\t[*] Found target bb: " << curr_filename << ":" << curr_line << "\n";
          errs() << "\t\t[*] Current bb: " << curr_filename << ":" << curr_line << "\n";
          ftarget << target_file << ":" << target_line << ",";
          ftarget << F.getName().str() << "\n";
        }
      }
    }
  }
  ftarget.close();
  return 0;
}

static RegisterPass<getFunctionName> X("getFunctionName", "Get Function Name Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);