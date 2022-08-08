using NaiveWallet

include("../src/wallet.jl")

@testset "Etherium address" begin
    k = "f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315"
    @test EtheriumPrivateToAddress(HexString(k)) == "001d3f1ef827552ae1114027bd3ecf1f086ba0f9"
end
