using NaiveWallet

include("../src/elliptic_curves.jl")

@testset "ECDSA" begin
   @test validPoint(secp256k1N*G)
   @test secp256k1N*G == I

   k = hex2int("f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315")
   K = k*G
   @test validPoint(K)

   @test string(K.x.v,base=16) == "6e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b"
   @test string(K.y.v,base=16) == "83b5c38e5e2b0c8529d7fa3f64d46daa1ece2d9ac14cab9477d042c84c32ccd0"
end
