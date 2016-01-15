{ rustPlatform, holmes, bap-rust }:
with rustPlatform;

buildRustPackage rec {
  name = "tiamat";
  src  = ./.;
  buildInputs = [ holmes bap-rust ];
  depsSha256 = "";
}
