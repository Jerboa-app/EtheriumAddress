module NaiveWallet

using HTTP

export SHA256, KECCAK256, HexString, EtherScanBalance
include("utils.jl")
include("hash.jl")
include("elliptic_curves.jl")
include("wallet.jl")

end # module
