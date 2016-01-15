{ pkgs ? (import <nixpkgs> {}).pkgs, local ? (import <local> {}).pkgs}:

with pkgs;
let holmes = callPackage ./holmes/package.nix {};
    bap-rust = callPackage ./bap-rust {pkgs = local;}; in

callPackage ./package.nix {inherit holmes bap-rust;}
