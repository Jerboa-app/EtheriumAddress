# sha256

function preprocessing(input::String)
	message_in = [UInt8(c) for c in input]

	msg_count = length(message_in)
	msg_bits = msg_count * 8
	appended_zero_bytes = mod(448 - (msg_bits + 1), 512)
	message_array = vcat(message_in, [0x80], UInt8.(zeros(Int(floor((appended_zero_bytes + 1) / 8) - 1))),reverse(reinterpret(UInt8, [msg_bits])))
	n_blocks = Int(ceil(length(message_array) / 64))

	output = zeros(UInt32, 16 * n_blocks)

	for i in 1:(16 * n_blocks)
		temp::UInt32 = 0
		for j in 1:4
			temp <<= 8
			temp = temp | message_array[4 * (i - 1) + j]
		end
		output[i] = temp
	end
	output
end

h0 = 0x6a09e667
h1 = 0xbb67ae85
h2 = 0x3c6ef372
h3 = 0xa54ff53a
h4 = 0x510e527f
h5 = 0x9b05688c
h6 = 0x1f83d9ab
h7 = 0x5be0cd19

k = [
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

function hash_chunk(chunk,hash=[h0,h1,h2,h3,h4,h5,h6,h7])

    h0 = hash[1]
    h1 = hash[2]
    h2 = hash[3]
    h3 = hash[4]
    h4 = hash[5]
    h5 = hash[6]
    h6 = hash[7]
    h7 = hash[8]

    w = Array{UInt32,1}(zeros(64));
    for i in 1:16
        w[i] = chunk[i]
    end

    for i in 17:64
        s0 = bitrotate(w[i-15],-7) ⊻ bitrotate(w[i-15],-18) ⊻ w[i-15]>>3
        s1 = bitrotate(w[i-2],-17) ⊻ bitrotate(w[i-2],-19) ⊻ w[i-2]>>10
        w[i] = w[i-16] + s0 + w[i-7] + s1
    end

    a = h0
    b = h1
    c = h2
    d = h3
    e = h4
    f = h5
    g = h6
    h = h7

    for i in 1:64
        S1 = bitrotate(e,-6) ⊻ bitrotate(e,-11) ⊻ bitrotate(e,-25)
        ch = (e & f) ⊻ ((~e) & g)
        temp1 = h + S1 + ch + k[i] + w[i]
        S0 = bitrotate(a,-2) ⊻ bitrotate(a,-13) ⊻ bitrotate(a,-22)
        maj = (a & b) ⊻ (a & c) ⊻ (b & c)
        temp2 = S0 + maj

        h = g
        g = f
        f = e
        e = d+temp1
        d = c
        c = b
        b = a
        a = temp1 + temp2
    end

    h0 = h0+a
    h1 = h1+b
    h2 = h2+c
    h3 = h3+d
    h4 = h4+e
    h5 = h5+f
    h6 = h6+g
    h7 = h7+h

    return [h0,h1,h2,h3,h4,h5,h6,h7]
end

function SHA256(input::String)
    chunks = preprocessing(input)
    blocks = Int(ceil(length(chunks) / 16))

    current_hash = [h0,h1,h2,h3,h4,h5,h6,h7]
    for i in 1:blocks
        current_hash = hash_chunk(chunks[(i-1)*16+1:(i*16)],current_hash)
    end
    return bytes2hex(reverse(reinterpret(UInt8,reverse(current_hash))));
end

# sha256 ends

# keccak / sha3

function ⊕(x,y)
    @assert length(x) == length(y)
    return x .⊻ y
end

function keccak256BitsToState(bits,w=64)
    A = Bool.(zeros(5,5,w))
    for x in 0:4
        for y in 0:4
            for z in 0:(w-1)
                A[x+1,y+1,z+1] = bits[w*(5*y+x)+z+1]
            end
        end
    end
    return A
end

function keccak256StateToBits(A,w=64)
    S = Vector{Bool}(zeros(5*5*w))
    l = 1
    for j in 1:5
        for i in 1:5
            for k in 1:w
                S[l] = A[i,j,k]
                l += 1
            end
        end
    end
    return S
end

function keccakθ(A,w=64)
    C = Bool.(zeros(5,w))
    D = Bool.(zeros(5,w))
    Ap = Bool.(zeros(5,5,w))

    for x in 1:5
        for z in 1:w
            C[x,z] = A[x,1,z] ⊕ A[x,2,z] ⊕ A[x,3,z] ⊕ A[x,4,z] ⊕ A[x,5,z]
        end
    end

    for x in 0:4
        for z in 0:(w-1)
            D[x+1,z+1] = C[mod( (x-1) , 5)+1,z+1] ⊕ C[mod( (x+1) , 5)+1,mod( z-1 , w)+1]
        end
    end

    for x in 1:5
        for y in 1:5
            for z in 1:w
                Ap[x,y,z] = A[x,y,z] ⊕ D[x,z]
            end
        end
    end
    return Ap
end

function keccakρ(A,w=64)
    Ap = Bool.(zeros(5,5,w))
    for z in 1:w
        Ap[1,1,z] = A[1,1,z]
    end
    x,y = (1,0)

    for t in 0:23
        for z in 0:(w-1)
            Ap[x+1,y+1,z+1] = A[x+1,y+1,mod( Int(z-(t+1)*(t+2)/2) , w)+1]
        end
        x,y = (y,mod(2*x+3*y,5))
    end
    return Ap
end

function keccakπ(A,w=64)
    Ap = Bool.(zeros(5,5,w))
    for x in 0:4
        for y in 0:4
            for z in 0:(w-1)
                Ap[x+1,y+1,z+1] = A[mod( (x+3*y) , 5)+1,x+1,z+1]
            end
        end
    end
    return Ap
end

function keccakχ(A,w=64)
    Ap = Bool.(zeros(5,5,w))
    for x in 0:4
        for y in 0:4
            for z in 0:(w-1)
                Ap[x+1,y+1,z+1] = A[x+1,y+1,z+1] ⊕ ( ([A[mod( (x+1) , 5)+1,y+1,z+1]]⊕[1])[1]*A[mod( x+2 , 5 )+1,y+1,z+1] )
            end
        end
    end
    return Ap
end

function Trunc(s,X)
    return X[1:s]
end

@assert Trunc(2,[1,0,1,0,0]) == [1,0]

function keccakrc(t)
    if mod(t,255) == 0
        return 1
    end
    R = [1,0,0,0,0,0,0,0]
    for i in 1:(mod(t,255))
        R = [0,R...]
        R[1] = R[1] ⊻ R[9]
        R[5] = R[5] ⊻ R[9]
        R[6] = R[6] ⊻ R[9]
        R[7] = R[7] ⊻ R[9]
        R = Trunc(8,R)
    end
    return R[1]
end

function keccakι(A,iᵣ,w=64)
    Ap = copy(A)
    RC = Bool.(zeros(w))
    l = log2(w)
    for j in 0:l
        RC[Int(2^j)] = keccakrc(j+7*iᵣ)
    end
    for z in 1:w
        Ap[1,1,z] = Ap[1,1,z] ⊻ RC[z]
    end
    return Ap
end

keccakRnd(A,iᵣ) = keccakι(keccakχ(keccakπ(keccakρ(keccakθ(A)))),iᵣ)

function keccak_p(S,nᵣ,w=64)
    A = keccak256BitsToState(S,w)
    l = log2(w)
    for iᵣ in (12+2*l-nᵣ):(12+2*l-1)
        A = keccakRnd(A,iᵣ)
    end
    return keccak256StateToBits(A,w)
end

function keccakSponge(N,d,r;f::Function,pad::Function,b=5*5*64)
    P = cat(N,pad(r,length(N)),dims=1)

    n = Int(length(P) / r)
    c = b-r
    Pi = []
    for i in 1:n
        push!(Pi,P[((i-1)*r+1):(i)*r])
    end
    S = Bool.(zeros(b))
    C = Bool.(zeros(c))
    for i in 1:n
        arg = S ⊕ ([Pi[i]...,C...])
        S = f(arg)
    end
    k = 0
    Z = []
    while true
        Z = [Z...,Trunc(r,S)...]
        if d <= length(Z)
            return Trunc(d,Z)
        end
        S = f(S)
        k+=1
    end
end

function keccakPad(x,m)
	j = mod( -m-2, x)
	return [true,Bool.(zeros(j))...,true]
end

function keccakC(S;d,c,w=64)
    r = 1600-c

    keccakSponge(S,d,r,f=(S)->keccak_p(S,24,w),pad=keccakPad,b=5*5*w)
end

struct HexString
	value::String
end

HEX_DIGITS = "0123456789abcdefABCDEF"

function KECCAK256(M::HexString;eth=false)
	if M.value != ""
		U = unique(M.value)
		for string_digit in U
			@assert string_digit in HEX_DIGITS
		end
	end
	m = M.value
	if length(m) % 2 != 0
		m = "0"*m
	end
	S = hex2bits(m)
	if eth == false
		S = [S...,0,1]
	end
	return bytes2hex(bits2bytes(keccakC([S...],c=512,d=256)))
end

function KECCAK512(M::HexString)
	if M.value != ""
		U = unique(M.value)
		for string_digit in U
			@assert string_digit in HEX_DIGITS
		end
	end
	m = M.value
	if length(m) % 2 != 0
		m = "0"*m
	end
	S = hex2bits(m)
	S = [S...,0,1]
	return bytes2hex(bits2bytes(keccakC([S...],c=1024,d=512)))
end
# keccak / sha3 ends
