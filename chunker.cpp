#include "holmes.capnp.h"

#include <capnp/ez-rpc.h>
#include <kj/debug.h>

#include <iostream>
#include <memory>
#include <vector>

using holmes::Holmes;
using capnp::Orphan;

class ChunkSection final : public Holmes::Analysis::Server {
  public:
    kj::Promise<void> analyze(AnalyzeContext context) {
      std::string fileName;
      uint64_t base;
      capnp::Data::Reader contents(0);
      bool bssMode = false;
      auto orphanage = capnp::Orphanage::getForMessageContaining(context.getResults());
      for (auto arg : context.getParams().getContext()) {
        if (arg.getVar() == "fileName") {
          fileName = arg.getVal().getStringVal();
        } else if (arg.getVar() == "base") {
          base = arg.getVal().getAddrVal();
        } else if (arg.getVar() == "contents") {
          contents = arg.getVal().getBlobVal();
        } else if (arg.getVar() == "mode") {
          bssMode = (arg.getVal().getStringVal() == ".bss");
        }
      }
      std::vector<capnp::Orphan<Holmes::Fact> > derived;
      for (size_t i = 0; i < contents.size(); i++) {
        Orphan<Holmes::Fact> fact = orphanage.newOrphan<Holmes::Fact>();
        auto fb = fact.get();
        fb.setFactName("word128");
        auto ab = fb.initArgs(3);
        ab[0].setStringVal(fileName);
        ab[1].setAddrVal(base + i);
        if (bssMode) {
          Orphan<capnp::Data> bss = orphanage.newOrphan<capnp::Data>(16);
          ab[2].adoptBlobVal(kj::mv(bss));
        } else {
          size_t end = std::min(i + 16, contents.size());
          ab[2].setBlobVal(contents.slice(i, end));
        }
        derived.push_back(kj::mv(fact));
      }
      auto derivedBuilder = context.getResults().initDerived(derived.size());
      auto i = 0;
      while (!derived.empty()) {
        derivedBuilder.adoptWithCaveats(i++, kj::mv(derived.back()));
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
  prems[0].setFactName("section");
  auto args = prems[0].initArgs(6);
  args[0].setBound("fileName");
  args[1].setUnbound();
  args[2].setBound("base");
  args[3].setUnbound();
  args[4].setBound("contents");
  args[5].setBound("mode");

  request.setAnalysis(kj::heap<ChunkSection>());


  request.send().wait(waitScope);
  return 0;
}
