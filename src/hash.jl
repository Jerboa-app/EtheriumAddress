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
