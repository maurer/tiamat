{ rustUnstable, holmes, bap-rust }:

with rustUnstable;
buildRustPackage rec {
  name = "tiamat";
  src  = ./.;
  buildInputs = [ holmes bap-rust ];
  depsSha256 = "";
}
