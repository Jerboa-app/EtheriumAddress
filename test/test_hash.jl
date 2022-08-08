using NaiveWallet

include("../src/utils.jl")
include("../src/hash.jl")

"""
The most important test to make sure the hash functions are working as specified
in the NIST standard.

KECCAK256 is split into each section of the algorithm; theta, rho, pi, etc.
"""

@testset "keccak internals" begin
    s = rand([0,1],1600);
    A = keccak256BitsToState(s);
    @test keccak256StateToBits(A) == s
    @test ⊕([1,1,0,0] , [1,0,1,0]) == [0,1,1,0]
    @test Trunc(2,[1,0,1,0,0]) == [1,0]
    @test mod(11,5) == 1
    @test mod(-11,5) == 4
end

@testset "KECCAK256 test vectors" begin
    # test vectors from
    # https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
    # also in this directory (SHA3-256_Msg0.pdf)
    empty_after_theta = "07 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 0C 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 0C 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 0C 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 06 00 00 00 00 00 00 80 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 0C 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 00 00 0C 00 00 00 00 00 00 00"
    empty_after_theta = [hex2bytes(x)[1] for x in split(empty_after_theta," ")]

    empty_after_rho = "07 00 00 00 00 00 00 00 0C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 00 00 00 00 60 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 60 00 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 C0 00 00 00 00 00 08 00 00 00 00 00 00 00 00 18 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 D0 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 00 00 00 00 04 00 00 00 00 00 18 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 03 00 00 00 00 00"
    empty_after_rho = [hex2bytes(x)[1] for x in split(empty_after_rho," ")]

    empty_after_pi = "07 00 00 00 00 00 00 00 00 00 00 00 00 60 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 C0 00 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 D0 00 00 00 00 00 00 00 00 00 10 0C 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 60 00 00 00 00 00 00 00 00 10 00 00 00 00 18 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 02 00 00 18 00 00 00 00 00 00 00"
    empty_after_pi = [hex2bytes(x)[1] for x in split(empty_after_pi," ")]

    empty_after_chi = "07 00 00 00 00 04 00 00 00 00 00 00 00 60 00 00 00 00 03 00 00 04 00 00 07 00 00 00 00 00 00 00 00 00 03 00 00 60 00 00 08 00 00 00 00 00 00 00 00 00 C0 00 00 D0 00 00 08 00 00 00 00 00 00 10 00 00 00 00 00 D0 00 00 00 00 C0 00 00 00 00 10 0C 00 00 00 00 00 00 00 20 0C 00 00 00 00 00 00 00 00 04 00 00 00 00 00 0C 0C 00 00 00 00 00 00 20 00 04 00 00 00 00 00 00 18 00 60 00 00 00 00 00 40 00 00 10 00 00 00 00 18 00 00 00 00 00 00 00 40 00 60 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 06 00 20 00 00 00 00 00 00 00 00 18 00 00 00 00 06 00 00 00 00 00 00 00 02 00 20 18 00 00 00 00 00 00 00"
    empty_after_chi = [hex2bytes(x)[1] for x in split(empty_after_chi," ")]

    empty_after_iota = "06 00 00 00 00 04 00 00 00 00 00 00 00 60 00 00 00 00 03 00 00 04 00 00 07 00 00 00 00 00 00 00 00 00 03 00 00 60 00 00 08 00 00 00 00 00 00 00 00 00 C0 00 00 D0 00 00 08 00 00 00 00 00 00 10 00 00 00 00 00 D0 00 00 00 00 C0 00 00 00 00 10 0C 00 00 00 00 00 00 00 20 0C 00 00 00 00 00 00 00 00 04 00 00 00 00 00 0C 0C 00 00 00 00 00 00 20 00 04 00 00 00 00 00 00 18 00 60 00 00 00 00 00 40 00 00 10 00 00 00 00 18 00 00 00 00 00 00 00 40 00 60 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 06 00 20 00 00 00 00 00 00 00 00 18 00 00 00 00 06 00 00 00 00 00 00 00 02 00 20 18 00 00 00 00 00 00 00"
    empty_after_iota = [hex2bytes(x)[1] for x in split(empty_after_iota," ")]

    empty_after_rounds = "A7 FF C6 F8 BF 1E D7 66 51 C1 47 56 A0 61 D6 62 F5 80 FF 4D E4 3B 49 FA 82 D8 0A 4B 80 F8 43 4A 52 66 BE B7 34 6B F3 E2 66 95 CC CA 21 59 87 FF 89 BA B3 76 57 7B D9 80 3B 31 6A FC 55 BD DE 28 CC 8E E4 F1 19 3D AC 03 E9 34 E4 C1 EC 3A 19 78 79 1E E8 AF 23 A9 87 C2 33 1F 60 01 E3 4A 68 21 5F E7 09 9E 46 7E 2E 28 B8 B6 82 C2 D2 1E 7D D1 4E 43 AF AD D2 E0 50 F0 B0 89 A9 6A FB F6 75 53 1E F1 FA 32 60 B9 C6 C2 B2 A1 55 F0 D3 4D 68 63 B2 C2 8E 98 8B 39 08 D9 26 D3 0B 3E 90 10 3F 91 17 98 47 4D 66 34 FC 33 58 DE 8F 07 1A 5C 71 2B 79 97 36 51 92 7C 0B 14 5E EB BD AA A7 43 73 85 E5 70 7B FB 0E 6E 13 92"
    empty_after_rounds = [hex2bytes(x)[1] for x in split(empty_after_rounds," ")]

    empty_after_perm = "A7 FF C6 F8 BF 1E D7 66 51 C1 47 56 A0 61 D6 62 F5 80 FF 4D E4 3B 49 FA 82 D8 0A 4B 80 F8 43 4A 52 66 BE B7 34 6B F3 E2 66 95 CC CA 21 59 87 FF 89 BA B3 76 57 7B D9 80 3B 31 6A FC 55 BD DE 28 CC 8E E4 F1 19 3D AC 03 E9 34 E4 C1 EC 3A 19 78 79 1E E8 AF 23 A9 87 C2 33 1F 60 01 E3 4A 68 21 5F E7 09 9E 46 7E 2E 28 B8 B6 82 C2 D2 1E 7D D1 4E 43 AF AD D2 E0 50 F0 B0 89 A9 6A FB F6 75 53 1E F1 FA 32 60 B9 C6 C2 B2 A1 55 F0 D3 4D 68 63 B2 C2 8E 98 8B 39 08 D9 26 D3 0B 3E 90 10 3F 91 17 98 47 4D 66 34 FC 33 58 DE 8F 07 1A 5C 71 2B 79 97 36 51 92 7C 0B 14 5E EB BD AA A7 43 73 85 E5 70 7B FB 0E 6E 13 92"
    empty_after_perm = [hex2bytes(x)[1] for x in split(empty_after_perm," ")]

    empty_hash = "A7 FF C6 F8 BF 1E D7 66 51 C1 47 56 A0 61 D6 62 F5 80 FF 4D E4 3B 49 FA 82 D8 0A 4B 80 F8 43 4A"
    empty_hash = [hex2bytes(x)[1] for x in split(empty_hash," ")]

    m = []

    d=256
    c=512
    w=64
    b = 5*5*w
    r=b-c

    N = [m...,0,1]
    P = [N...,keccakPad(r,length(N))...]
    n = Int(length(P) / r)
    c = b-r
    Pi = []
    for i in 1:n
        push!(Pi,P[((i-1)*r+1):(i)*r])
    end
    S = Bool.(zeros(b));
    C = Bool.(zeros(c))

    arg = S ⊕ ([Pi[1]...,C...]);

    s1 = keccak256StateToBits(keccakθ(keccak256BitsToState(arg)));
    @test bits2bytes(s1) == empty_after_theta

    s2 = keccak256StateToBits(keccakρ(keccakθ(keccak256BitsToState(arg))));
    @test bits2bytes(s2) == empty_after_rho

    s3 = keccak256StateToBits(keccakπ(keccakρ(keccakθ(keccak256BitsToState(arg)))));
    @test bits2bytes(s3) == empty_after_pi

    s4 = keccak256StateToBits(keccakχ(keccakπ(keccakρ(keccakθ(keccak256BitsToState(arg))))));
    @test bits2bytes(s4) == empty_after_chi

    nᵣ=24
    A = keccak256BitsToState(arg)
    l = log2(w)
    for iᵣ in [(12+2*l-nᵣ)]
        A = keccakRnd(A,iᵣ)
    end
    s5 = keccak256StateToBits(A)
    @test bits2bytes(s5) == empty_after_iota

    nᵣ=24
    A = keccak256BitsToState(arg)
    l = log2(w)
    for iᵣ in (12+2*l-nᵣ):(12+2*l-1)
        A = keccakRnd(A,iᵣ)
    end
    s5 = keccak256StateToBits(A)
    @test bits2bytes(s5) == empty_after_rounds

    S = s5

    k = 0
    Z = []
    while true
        Z = [Z...,Trunc(r,S)...]
        if d <= length(Z)
            Z = Trunc(d,Z)
            break
        end
        S = keccak_p(S,nᵣ,w=64)
        k+=1
    end
    @test bits2bytes(Z) == empty_hash

    @test KECCAK256(HexString("")) == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    @test KECCAK256(HexString(""),eth=true) == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    @test KECCAK256(HexString("6e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b83b5c38e5e2b0c8529d7fa3f64d46daa1ece2d9ac14cab9477d042c84c32ccd0"),eth=true) == "2a5bc342ed616b5ba5732269001d3f1ef827552ae1114027bd3ecf1f086ba0f9"
end
