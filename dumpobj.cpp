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

using llvm::dyn_cast;
using holmes::Holmes;
using capnp::Orphan;
using kj::mv;
using llvm::OwningPtr;
using llvm::object::Binary;
using llvm::MemoryBuffer;
using llvm::Triple;
using llvm::object::ObjectFile;

class DumpObj final : public Holmes::Analysis::Server {
  public:
    kj::Promise<void> analyze(AnalyzeContext context) {
      auto prems = context.getParams().getPremises();
      auto orphanage = capnp::Orphanage::getForMessageContaining(context.getResults());
      std::vector<capnp::Orphan<Holmes::Fact> > derived;
      
      auto args = prems[0].getArgs();
      auto fileName = args[0].getStringVal();
      auto body = args[1].getBlobVal();
      
      auto sr = llvm::StringRef(reinterpret_cast<const char*>(body.begin()), body.size());
      auto mb = llvm::MemoryBuffer::getMemBuffer(sr, "holmes-input", false);
      llvm::OwningPtr<llvm::object::Binary> oBin(0);
      if (llvm::object::createBinary(mb, oBin)) {
        //We failed to parse the binary
        Orphan<Holmes::Fact> fact = orphanage.newOrphan<Holmes::Fact>();
        auto fb = fact.get();
        fb.setFactName("llvm-obj-no-parse");
        auto ab = fb.initArgs(1);
        ab[0].setStringVal(fileName);
        derived.push_back(mv(fact));
      } else {
        llvm::object::Binary *bin = oBin.take();
        if (llvm::object::Archive *a = dyn_cast<llvm::object::Archive>(bin)) {
          Orphan<Holmes::Fact> fact = orphanage.newOrphan<Holmes::Fact>();
          auto fb = fact.get();
          fb.setFactName("is-archive");
          auto ab = fb.initArgs(1);
          ab[0].setStringVal(fileName);
          derived.push_back(mv(fact));
          for (auto i = a->begin_children(), e = a->end_children(); i != e; ++i) {
            OwningPtr<Binary> b;
            if (!i->getAsBinary(b)) {
              Orphan<Holmes::Fact> fact = orphanage.newOrphan<Holmes::Fact>();
              auto fb = fact.get();
              fb.setFactName("file");
              auto ab = fb.initArgs(2);
              ab[0].setStringVal(std::string(fileName) + ":" + std::string(b->getFileName()));
              OwningPtr<MemoryBuffer> omb;
              i->getMemoryBuffer(omb);
              ab[1].setBlobVal(capnp::Data::Reader(reinterpret_cast<const unsigned char*>(omb->getBufferStart()), omb->getBufferSize()));
              derived.push_back(mv(fact));
            }
          }
        } else if (llvm::object::ObjectFile *o = dyn_cast<llvm::object::ObjectFile>(bin)) {
          {
            //Note that it's an object
            Orphan<Holmes::Fact> fact = orphanage.newOrphan<Holmes::Fact>();
            auto fb = fact.get();
            fb.setFactName("is-object");
            auto ab = fb.initArgs(1);
            ab[0].setStringVal(fileName);
            derived.push_back(mv(fact));
          }
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
          llvm::error_code ec_ignore;
          for (auto i = o->begin_sections(), e = o->end_sections(); i != e; i = i.increment(ec_ignore)) {
            Orphan<Holmes::Fact> fact = orphanage.newOrphan<Holmes::Fact>();
            auto fb = fact.get();
            fb.setFactName("section");
            auto ab = fb.initArgs(6);
            llvm::StringRef name;
            uint64_t base;
            uint64_t size;
            llvm::StringRef contents;
            i->getName(name);
            i->getAddress(base);
            i->getSize(size);
            i->getContents(contents);
            ab[1].setStringVal(std::string(name));
            ab[2].setAddrVal(base);
            ab[3].setAddrVal(size);
            bool text, rodata, data, bss;
            i->isText(text);
            i->isReadOnlyData(rodata);
            i->isData(data);
            i->isBSS(bss);
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
          for (auto i = o->begin_symbols(), e = o->end_symbols(); i != e; i = i.increment(ec_ignore)) {
            llvm::StringRef symName;
            uint64_t  symAddr;
            uint64_t  symSize;
            llvm::object::SymbolRef::Type symType;
            uint64_t  symVal;
            i->getName(symName);
            i->getAddress(symAddr);
            i->getSize(symSize);
            i->getType(symType);
            i->getValue(symVal);
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
            auto ab = fb.initArgs(6);
            ab[0].setStringVal(fileName);
            ab[1].setStringVal(std::string(symName));
            ab[2].setAddrVal(symAddr);
            ab[3].setAddrVal(symSize);
            ab[4].setAddrVal(symVal);
            ab[5].setStringVal(symTypeStr);
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
  
  auto request = holmes.analyzerRequest();
  auto prems = request.initPremises(1);
  prems[0].setFactName("file");
  auto args = prems[0].initArgs(2);
  args[0].setBound("fileName");
  args[1].setUnbound();

  request.setAnalysis(kj::heap<DumpObj>());

  request.send().wait(waitScope);
  return 0;
}
