#include "holmes.capnp.h"

#include <capnp/ez-rpc.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/Archive.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/ADT/Triple.h>
#include <llvm/Support/MemoryBuffer.h>
#include <kj/debug.h>

#include <iostream>
#include <memory>
#include <vector>
#include <assert.h>

using llvm::dyn_cast;
using holmes::Holmes;
using capnp::Orphan;
using kj::mv;
using llvm::object::Binary;
using llvm::MemoryBuffer;
using llvm::Triple;
using llvm::object::ObjectFile;
using namespace llvm;

#define FILENAME 0
#define BODY 1

class DumpObj final : public Holmes::Analysis::Server {
  public:
    kj::Promise<void> analyze(AnalyzeContext context) {
      auto ctx = context.getParams().getContext();
      auto orphanage = capnp::Orphanage::getForMessageContaining(context.getResults());
      std::vector<capnp::Orphan<Holmes::Fact> > derived;
      std::string fileName(ctx[FILENAME].getStringVal());
      capnp::Data::Reader body(ctx[BODY].getBlobVal());
      
      auto sr = llvm::StringRef(reinterpret_cast<const char*>(body.begin()), body.size());
      auto mb = llvm::MemoryBuffer::getMemBuffer(sr, "holmes-input", false);
      auto maybeBin = llvm::object::createBinary(mb);  
      if (std::error_code EC = maybeBin.getError()) {
        //We failed to parse the binary
        Orphan<Holmes::Fact> fact = orphanage.newOrphan<Holmes::Fact>();
        auto fb = fact.get();
        fb.setFactName("llvm-obj-no-parse");
        auto ab = fb.initArgs(1);
        ab[0].setStringVal(fileName);
        derived.push_back(mv(fact));
      } else {
        llvm::object::Binary *bin = maybeBin.get();
        if (llvm::object::Archive *a = dyn_cast<llvm::object::Archive>(bin)) {
          Orphan<Holmes::Fact> fact = orphanage.newOrphan<Holmes::Fact>();
          auto fb = fact.get();
          fb.setFactName("is-archive");
          auto ab = fb.initArgs(1);
          ab[0].setStringVal(fileName);
          derived.push_back(mv(fact));
          for (auto i = a->child_begin(), e = a->child_end(); i != e; ++i) {
            ErrorOr<std::unique_ptr<Binary>> maybeChild = i->getAsBinary();
            if (ObjectFile *b = dyn_cast<ObjectFile>(&*maybeChild.get())) {
              Orphan<Holmes::Fact> fact = orphanage.newOrphan<Holmes::Fact>();
              auto fb = fact.get();
              fb.setFactName("file");
              auto ab = fb.initArgs(2);
              ab[0].setStringVal(std::string(fileName) + ":" + std::string(b->getFileName()));
              auto ir = i->getMemoryBuffer();
              ab[1].setBlobVal(capnp::Data::Reader(reinterpret_cast<const unsigned char*>(ir.get()->getBufferStart()), ir.get()->getBufferSize()));
              derived.push_back(mv(fact));
            }
          }
        } else if (llvm::object::ObjectFile *o = dyn_cast<llvm::object::ObjectFile>(bin)) {
          {
            //Export its architecture
            Orphan<Holmes::Fact> fact = orphanage.newOrphan<Holmes::Fact>();
            auto fb = fact.get();
            fb.setFactName("arch");
            auto ab = fb.initArgs(2);
            ab[0].setStringVal(fileName);
            ab[1].setStringVal(Triple::getArchTypeName(Triple::ArchType(o->getArch())));
            derived.push_back(mv(fact));
          }
          std::error_code ec_ignore;
          for (auto i : o->sections()) {
            Orphan<Holmes::Fact> fact = orphanage.newOrphan<Holmes::Fact>();
            auto fb = fact.get();
            fb.setFactName("section");
            auto ab = fb.initArgs(6);
            llvm::StringRef name;
            uint64_t base;
            uint64_t size;
            llvm::StringRef contents;
            i.getName(name);
            i.getAddress(base);
            i.getSize(size);
            i.getContents(contents);
            ab[1].setStringVal(std::string(name));
            ab[2].setAddrVal(base);
            ab[3].setAddrVal(size);
            bool text, rodata, data, bss;
            i.isText(text);
            i.isReadOnlyData(rodata);
            i.isData(data);
            i.isBSS(bss);
            if (!bss) {
              ab[4].setBlobVal(capnp::Data::Reader(reinterpret_cast<const unsigned char*>(contents.begin()), contents.size()));
            } else {
              ab[4].setBlobVal(capnp::Data::Reader(0));
            }
            if (text) {
              ab[5].setStringVal(".text");
            } else if (rodata) {
              ab[5].setStringVal(".rodata");
            } else if (data) {
              ab[5].setStringVal(".data");
            } else if (bss) {
              ab[5].setStringVal(".bss");
            } else {
              ab[5].setStringVal(".unk");
            }
            ab[0].setStringVal(fileName);
            derived.push_back(mv(fact));
          }
          for (auto i : o->symbols()) {
            llvm::StringRef symName;
            uint64_t  symAddr;
            uint64_t  symSize;
            llvm::object::SymbolRef::Type symType;
            i.getName(symName);
            i.getAddress(symAddr);
            i.getSize(symSize);
            i.getType(symType);
            std::string symTypeStr;
            switch (symType) {
              case llvm::object::SymbolRef::Type::ST_Unknown:
                symTypeStr = "unknown"; break;
              case llvm::object::SymbolRef::Type::ST_Data:
                symTypeStr = "data"; break;
              case llvm::object::SymbolRef::Type::ST_Debug:
                symTypeStr = "debug"; break;
              case llvm::object::SymbolRef::Type::ST_File:
                symTypeStr = "file"; break;
              case llvm::object::SymbolRef::Type::ST_Function:
                symTypeStr = "func"; break;
              case llvm::object::SymbolRef::Type::ST_Other:
                symTypeStr = "other"; break;
            }
            
            Orphan<Holmes::Fact> fact = orphanage.newOrphan<Holmes::Fact>();
            auto fb = fact.get();
            fb.setFactName("symbol");
            auto ab = fb.initArgs(5);
            ab[0].setStringVal(fileName);
            ab[1].setStringVal(std::string(symName));
            ab[2].setAddrVal(symAddr);
            ab[3].setAddrVal(symSize);
            ab[4].setStringVal(symTypeStr);
            derived.push_back(mv(fact));
          } 
        }
      }
      auto derivedBuilder = context.getResults().initDerived(derived.size());
      auto i = 0;
      while (!derived.empty()) {
        derivedBuilder.adoptWithCaveats(i++, mv(derived.back()));
        derived.pop_back();
      }
      return kj::READY_NOW;
    }
};

int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cerr << "usage: " << argv[0] << " HOST:PORT" << std::endl;
    return 1;
  }
  capnp::EzRpcClient client(argv[1]);
  holmes::Holmes::Client holmes = client.importCap<holmes::Holmes>("holmes");
  auto& waitScope = client.getWaitScope();
  
  //Register fact types
  auto fileReq = holmes.registerTypeRequest();
  fileReq.setFactName("file");
  auto fileArgTypes = fileReq.initArgTypes(2);
  fileArgTypes.set(0, holmes::Holmes::HType::STRING);
  fileArgTypes.set(1, holmes::Holmes::HType::BLOB);
  auto fileRes = fileReq.send();

  auto symReq = holmes.registerTypeRequest();
  symReq.setFactName("symbol");
  auto symArgTypes = symReq.initArgTypes(5);
  symArgTypes.set(0, holmes::Holmes::HType::STRING);
  symArgTypes.set(1, holmes::Holmes::HType::STRING);
  symArgTypes.set(2, holmes::Holmes::HType::ADDR);
  symArgTypes.set(3, holmes::Holmes::HType::ADDR);
  symArgTypes.set(4, holmes::Holmes::HType::STRING);
  auto symRes = symReq.send();

  auto sectReq = holmes.registerTypeRequest();
  sectReq.setFactName("section");
  auto sectArgTypes = sectReq.initArgTypes(6);
  sectArgTypes.set(0, holmes::Holmes::HType::STRING);
  sectArgTypes.set(1, holmes::Holmes::HType::STRING);
  sectArgTypes.set(2, holmes::Holmes::HType::ADDR);
  sectArgTypes.set(3, holmes::Holmes::HType::ADDR);
  sectArgTypes.set(4, holmes::Holmes::HType::BLOB);
  sectArgTypes.set(5, holmes::Holmes::HType::STRING);
  auto sectRes = sectReq.send();

  auto archReq = holmes.registerTypeRequest();
  archReq.setFactName("arch");
  auto archArgTypes = archReq.initArgTypes(2);
  archArgTypes.set(0, holmes::Holmes::HType::STRING);
  archArgTypes.set(1, holmes::Holmes::HType::STRING);
  auto archRes = archReq.send();

  //Resolve registration
  assert(fileRes.wait(waitScope).getValid());
  assert(symRes.wait(waitScope).getValid());
  assert(sectRes.wait(waitScope).getValid());
  assert(archRes.wait(waitScope).getValid());

  //Activate Analysis
  auto request = holmes.analyzerRequest();
  auto prems = request.initPremises(1);
  prems[0].setFactName("file");
  auto args = prems[0].initArgs(2);
  args[0].setBound(FILENAME);
  args[1].setBound(BODY);

  request.setAnalysis(kj::heap<DumpObj>());
  
  request.setName("dumpObj");

  request.send().wait(waitScope);
  return 0;
}
